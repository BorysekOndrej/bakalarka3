import app
import app.db_models

# from loguru import logger
logger = app.logger

from sqlalchemy.exc import IntegrityError
import json
import datetime

import app.utils.certificate as certificate
import app.utils.db_utils as db_utils
import app.utils.files as files

still_to_parse_test = True


def try_to_add(obj):
    try:
        app.db.add(obj)
        app.db.commit()
    except IntegrityError as _:
        logger.error("IntegrityError on inserting object (possible duplicity): " + str(obj))
        app.db.rollback()


def basic_db_fill_test():
    logger.debug("DB Basic fill test started")

    # scan_result = ScanResult(scanTargetID=1, scanType="TEST-TYPE", duration=0, status=404, result="TEST-RESULT")
    # try_to_add(scan_result)

    logger.debug("DB Basic fill test finished")


def parse_cipher_suite(scan_result, plugin_title):
    protocol_str = plugin_title[:].replace(" Cipher Suites", "")
    print(plugin_title)

    res = app.db_models.CipherSuiteScanResult()
    res.protocol = protocol_str
    res.preferred_cipher_id = app.db_models.AcceptedCipherSuite.from_dict(scan_result["results"][plugin_title][
                                                                              "preferred_cipher"])

    plugin_fields = {
        # "preferred_cipher": {"elem_type": AcceptedCipherSuite, "expected_fields": ["openssl_name", "ssl_version", "is_anonymous", "key_size", "post_handshake_response"]},
        "accepted_cipher_list": {"elem_type": app.db_models.AcceptedCipherSuite,
                                 "expected_fields": ["openssl_name", "ssl_version", "is_anonymous", "key_size",
                                                     "post_handshake_response"]},
        "rejected_cipher_list": {"elem_type": app.db_models.RejectedCipherSuite,
                                 "expected_fields": ["openssl_name", "ssl_version", "is_anonymous",
                                                     "handshake_error_message"]},
        "errored_cipher_list": {},  # todo: errored_cipher_list
    }

    for plugin_field in plugin_fields:
        current_plugin_fields = plugin_fields[plugin_field]
        list_of_results = scan_result["results"][plugin_title][plugin_field]

        answer_list = []
        for single_cipher in list_of_results:
            assert single_cipher is not None
            param_order = current_plugin_fields["expected_fields"]

            cipher_id = current_plugin_fields["elem_type"].from_dict(single_cipher)
            answer_list.append(cipher_id)

            if still_to_parse_test:
                for s_param in param_order:
                    single_cipher.pop(s_param, None)

        answer_string = str(answer_list)
        logger.info(f"{plugin_title}: {plugin_field}: {answer_string}")

        setattr(res, plugin_field, answer_string)

        if still_to_parse_test:
            scan_result["results"][plugin_title].pop("preferred_cipher", None)
            if scan_result["results"][plugin_title][plugin_field] is not None:
                scan_result["results"][plugin_title][plugin_field] = list(
                    filter(None, scan_result["results"][plugin_title][plugin_field]))
            if scan_result["results"][plugin_title][plugin_field] is None or len(
                    scan_result["results"][plugin_title][plugin_field]) == 0:
                scan_result["results"][plugin_title].pop(plugin_field, None)

    res = db_utils.get_one_or_create_from_object(res)
    return res[0].id


def parse_server_info(scan_result):
    server_info_part = scan_result["server_info"]
    cipher_res_id = app.db_models.CipherSuite.id_from_parts(server_info_part["openssl_cipher_string_supported"],
                                                            server_info_part["highest_ssl_version_supported"])
    res = app.db_models.ServerInfo(hostname=server_info_part["hostname"], port=server_info_part["port"],
                                   ip_address=server_info_part["ip_address"],
                                   openssl_cipher_string_supported_id=cipher_res_id)
    res = db_utils.get_one_or_create_from_object(res)

    if still_to_parse_test:
        scan_result.pop("server_info")

    return res[0].id


def parse_certificate_chain(obj):
    answer = []
    for i in range(len(obj)):
        cur_crt = parse_certificate(obj[i])
        answer.append(cur_crt)

    return app.db_models.CertificateChain.from_list(answer)


def parse_single_ocsp_response(obj):
    crt_obj = db_utils.dict_filter_to_class_variables(app.db_models.OCSPResponseSingle, obj)

    crt_obj["certID_hashAlgorithm"] = obj["certID"]["hashAlgorithm"]
    crt_obj["certID_issuerNameHash"] = obj["certID"]["issuerNameHash"]
    crt_obj["certID_issuerKeyHash"] = obj["certID"]["issuerKeyHash"]
    crt_obj["certID_serialNumber"] = obj["certID"]["serialNumber"]

    crt_obj["thisUpdate"] = datetime.datetime.strptime(obj["thisUpdate"], '%b %d %H:%M:%S %Y %Z')
    crt_obj["nextUpdate"] = datetime.datetime.strptime(obj["nextUpdate"], '%b %d %H:%M:%S %Y %Z')

    res = db_utils.get_one_or_create(app.db_models.OCSPResponseSingle, **crt_obj)
    return res[0].id


def parse_certificate_information_ocsp_response(obj):
    obj["responses_list"] = []
    for x in obj["responses"]:
        obj["responses_list"].append(parse_single_ocsp_response(x))

    obj["producedAt"] = datetime.datetime.strptime(obj["producedAt"], '%b %d %H:%M:%S %Y %Z')
    obj["responses_list"] = ",".join(str(x) for x in obj["responses_list"])

    crt_obj = db_utils.dict_filter_to_class_variables(app.db_models.OCSPResponse, obj)
    res = app.db_models.OCSPResponse.from_kwargs(crt_obj)

    if still_to_parse_test:
        obj.pop("responses")

    return res


def parse_certificate_information(scan_result, plugin_title):
    current_plugin = scan_result["results"][plugin_title]
    logger.debug(current_plugin)

    current_plugin["received_certificate_chain_list_id"] = parse_certificate_chain(current_plugin[
                                                                                       "received_certificate_chain"])
    current_plugin["verified_certificate_chain_list_id"] = parse_certificate_chain(current_plugin[
                                                                                       "verified_certificate_chain"])
    current_plugin["validated_paths_list"] = []
    for validated_paths in current_plugin["path_validation_result_list"]:
        trust_store = app.db_models.TrustStore.from_dict(validated_paths["trust_store"])
        chain = parse_certificate_chain(validated_paths["verified_certificate_chain"])
        verify_string = validated_paths["verify_string"]

        current_plugin["validated_paths_list"].append(  # todo
            {"trust_store": trust_store, "chain": chain, "verify_string": verify_string})

    current_plugin["ocsp_response_id"] = parse_certificate_information_ocsp_response(current_plugin["ocsp_response"])
    tmp_validated_path_ids = []

    for validated_path in current_plugin["validated_paths_list"]:
        new_id = app.db_models.ValidatedPath.from_kwargs({"trust_store_id": validated_path["trust_store"],
                                                          "chain_id": validated_path["chain"],
                                                          "verify_string": validated_path["verify_string"],
                                                          })
        tmp_validated_path_ids.append(str(new_id))
    current_plugin["path_validation_result_list"] = ", ".join(tmp_validated_path_ids)
    current_plugin.pop("validated_paths_list")
    prep_obj = db_utils.dict_filter_to_class_variables(app.db_models.CertificateInformation, current_plugin)
    # prep_obj["path_validation_error_list"] = ",".join(prep_obj["path_validation_error_list"])

    prep_obj.pop("ocsp_response")
    prep_obj.pop("path_validation_error_list")
    # prep_obj.pop("path_validation_result_list") # todo

    res = db_utils.get_one_or_create(app.db_models.CertificateInformation, **prep_obj)

    # logger.error([x for x in current_plugin.keys() if "certificate_chain" in x])
    if still_to_parse_test:
        current_plugin.pop("received_certificate_chain")
        current_plugin.pop("verified_certificate_chain")
        current_plugin.pop("path_validation_result_list")
        current_plugin.pop("ocsp_response")
        scan_result["results"].pop(plugin_title)

    return res[0].id


def parse_certificate(obj):
    try:
        crt_obj = db_utils.dict_filter_to_class_variables(app.db_models.Certificate, obj)
        crt_obj["thumbprint_sha1"] = certificate.certificate_thumbprint(crt_obj["as_pem"], "sha1")
        crt_obj["thumbprint_sha256"] = certificate.certificate_thumbprint(crt_obj["as_pem"], "sha256")

        crt_obj["publicKey_algorithm"] = obj["publicKey"]["algorithm"]
        crt_obj["publicKey_size"] = obj["publicKey"]["size"]
        crt_obj["publicKey_curve"] = obj["publicKey"].get("curve", None)
        crt_obj["publicKey_exponent"] = obj["publicKey"].get("exponent", None)

        crt_obj["notBefore"] = datetime.datetime.strptime(obj["notBefore"], '%Y-%m-%d %H:%M:%S')
        crt_obj["notAfter"] = datetime.datetime.strptime(obj["notAfter"], '%Y-%m-%d %H:%M:%S')

        crt_obj["subject_alternative_name_list"] = ",".join(obj.get("subjectAlternativeName", {}).get("DNS", []))
    except Exception as e:
        logger.exception(e)
        logger.error(obj)

    res = db_utils.get_one_or_create(app.db_models.Certificate, **crt_obj)
    return res[0].id


def parse_http_security_headers(scan_result, plugin_title):
    current_plugin = scan_result["results"][plugin_title]
    current_plugin["verified_certificate_chain_list_id"] = parse_certificate_chain(current_plugin[
                                                                                       "verified_certificate_chain"])
    prep_obj = db_utils.dict_filter_to_class_variables(app.db_models.Certificate, current_plugin)
    prep_obj["expect_ct_header_max_age"] = current_plugin["expect_ct_header"]["max_age"]
    prep_obj["expect_ct_header_report_uri"] = current_plugin["expect_ct_header"]["report_uri"]
    prep_obj["expect_ct_header_enforce"] = current_plugin["expect_ct_header"]["enforce"]

    res = db_utils.get_one_or_create(app.db_models.HTTPSecurityHeaders, **prep_obj)

    if still_to_parse_test:
        current_plugin.pop("verified_certificate_chain")
        scan_result["results"].pop(plugin_title)

    return res[0].id


def parse_tls12_session_resumption(class_type, scan_result, plugin_title):
    current_plugin = scan_result["results"][plugin_title]
    current_plugin["errored_resumptions_list"] = ",".join(current_plugin["errored_resumptions_list"])
    kwargs = db_utils.dict_filter_to_class_variables(class_type, current_plugin)
    res = class_type.from_kwargs(kwargs)
    if still_to_parse_test:
        scan_result["results"].pop(plugin_title)
    return res


def parse_general(class_type, scan_result, plugin_title):
    current_plugin = scan_result["results"][plugin_title]
    res = class_type.from_kwargs(current_plugin)
    if still_to_parse_test:
        scan_result["results"].pop(plugin_title)
    return res


@logger.catch
def run():
    # basic_db_fill_test(session)
    scan_result_string = files.read_from_file("../tmp/test_copy.out.json")
    scan_result = json.loads(scan_result_string)

    obj = app.db_models.ScanResults()

    general_parser_matching = {
        "Deflate Compression": app.db_models.DeflateCompression,
        "Session Renegotiation": app.db_models.SessionRenegotiation,
        "TLS 1.3 Early Data": app.db_models.TLS13EarlyData,
        "OpenSSL CCS Injection": app.db_models.OpenSSLCCSInjection,
        "OpenSSL Heartbleed": app.db_models.OpenSSLHeartbleed,
        "Downgrade Attacks": app.db_models.DowngradeAttack,
        "ROBOT Attack": app.db_models.ROBOTAttack,
        "TLS 1.2 Session Resumption Rate": app.db_models.TLS12SessionResumptionRate,
    }

    for plugin_title in scan_result["results"]:
        if " Cipher Suites" in plugin_title:
            new_title = plugin_title[:] \
                .replace(" Cipher Suites", "") \
                .replace(".", "") \
                .replace(" ", "") \
                .replace("_", "") \
                .lower()
            new_title += "_id"
            x = parse_cipher_suite(scan_result, plugin_title)
            setattr(obj, new_title, x)

    if scan_result["results"].get("Certificate Information", None):
        # this expects Ciphers Suites to be parsed
        obj.certificate_information_id = parse_certificate_information(scan_result, "Certificate Information")

    if scan_result["results"].get("HTTP Security Headers", None):
        # this expects Ciphers Suites to be parsed
        obj.http_security_headers_id = parse_http_security_headers(scan_result, "HTTP Security Headers")

    if scan_result["results"].get("TLS 1.2 Session Resumption Support", None):
        # this expects Ciphers Suites to be parsed
        obj.tls_12_session_resumption_support_id = parse_tls12_session_resumption(
            app.db_models.TLS12SessionResumptionSupport,
            scan_result,
            "TLS 1.2 Session Resumption Support")

    if scan_result["results"].get("TLS 1.2 Session Resumption Rate", None):
        # this expects Ciphers Suites to be parsed
        obj.tls_12_session_resumption_rate_id = parse_tls12_session_resumption(app.db_models.TLS12SessionResumptionRate,
                                                                               scan_result,
                                                                               "TLS 1.2 Session Resumption Rate")

    for plugin_title in general_parser_matching:
        if scan_result["results"].get(plugin_title, None):
            x = parse_general(general_parser_matching[plugin_title], scan_result, plugin_title)
            new_title = plugin_title.lower().replace(".", "").replace(" ", "_")
            new_title += "_id"
            setattr(obj, new_title, x)

    if scan_result.get("server_info", None):
        # this expects Ciphers Suites to be parsed
        obj.server_info_id = parse_server_info(scan_result)

    db_utils.get_one_or_create_from_object(obj)

    if still_to_parse_test:
        to_remove = []
        for plugin_title in scan_result["results"]:
            if not scan_result["results"][plugin_title]:
                to_remove.append(plugin_title)
        for plugin_title in to_remove:
            scan_result["results"].pop(plugin_title, None)
        files.write_to_file("../tmp/still_to_parse.out.json", json.dumps(scan_result, indent=3))
