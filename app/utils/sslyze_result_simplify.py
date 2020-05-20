import app.db_models as db_models
import app.db_schemas as db_schemas
import app.utils.db_utils as db_utils


def sslyze_grade(scan_result: db_models.ScanResults):
    # todo: use grading module
    return "D"


# todo: maybe persist to DB?
def sslyze_result_simplify(scan_result: db_models.ScanResults) -> db_models.ScanResultsSimplified:
    simple = db_models.ScanResultsSimplified()
    simple.id = scan_result.id
    simple.grade = sslyze_grade(scan_result)
    simple.received_certificate_chain_list_id = scan_result.certificate_information.received_certificate_chain_list_id

    trust_stores = set()
    verified_chain_list = scan_result.certificate_information.verified_certificate_chain_list
    received_chain_list = scan_result.certificate_information.received_certificate_chain_list

    if verified_chain_list:
        res_new = db_models.db.session \
            .query(db_models.ValidatedPath) \
            .filter(db_models.ValidatedPath.chain_id == verified_chain_list.id) \
            .all()
        # .filter(db_models.ValidatedPath.chain_id.in_(changed_targets)) \

        for sr in res_new:
            sr: db_models.ValidatedPath
            trust_stores.add(sr.trust_store.name)

    simple.validated_against_truststores_list = ", ".join(list(trust_stores))

    chain_for_dates = verified_chain_list if verified_chain_list else received_chain_list

    if chain_for_dates:
        simple.notAfter = db_models.datetime_to_timestamp(chain_for_dates.not_after())
        simple.notBefore = db_models.datetime_to_timestamp(chain_for_dates.not_before())

    simple.sslv2_working_ciphers_count = len(db_utils.split_array_to_tuple(scan_result.sslv2.accepted_cipher_list))
    simple.sslv3_working_ciphers_count = len(db_utils.split_array_to_tuple(scan_result.sslv2.accepted_cipher_list))
    simple.tlsv10_working_ciphers_count = len(db_utils.split_array_to_tuple(scan_result.tlsv1.accepted_cipher_list))
    simple.tlsv11_working_ciphers_count = len(db_utils.split_array_to_tuple(scan_result.tlsv11.accepted_cipher_list))
    simple.tlsv12_working_ciphers_count = len(db_utils.split_array_to_tuple(scan_result.tlsv12.accepted_cipher_list))
    simple.tlsv13_working_ciphers_count = len(db_utils.split_array_to_tuple(scan_result.tlsv13.accepted_cipher_list))

    # todo: maybe persist to DB?
    return simple
