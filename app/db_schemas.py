from marshmallow import fields
from marshmallow.fields import Pluck
from marshmallow_enum import EnumField
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, SQLAlchemySchema
from marshmallow_sqlalchemy.fields import Nested
import sslyze.ssl_settings

import app.db_models


def get_array_reschemed(model_cls, schema_cls, ids: str, many: bool = True):
    schema = schema_cls(many=many)
    json_dict = schema.dump(model_cls.select_from_list(ids))
    return json_dict


class BaseSchema(SQLAlchemySchema):
    class Meta:
        load_instance = True
        exclude = ("id",)


class TargetSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.Target
    protocol = EnumField(sslyze.ssl_settings.TlsWrappedProtocolEnum)


class UserSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.User


class ScanOrderSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.ScanOrder
        include_relationships = True
        include_fk = True  # this needs to be enabled for schema.load to work properly

    target = Nested(TargetSchema)
    user = Nested(UserSchema)


class CipherSuiteSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.CipherSuite


class TrustStoreSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.TrustStore


class CertificateSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.Certificate


class ServerInfoSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.ServerInfo
        include_relationships = True

    openssl_cipher_string_supported = Nested(CipherSuiteSchema)


class RejectedCipherHandshakeErrorMessageSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.RejectedCipherHandshakeErrorMessage


class AcceptedCipherPostHandshakeResponseSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.AcceptedCipherPostHandshakeResponse


class RejectedCipherSuiteSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.RejectedCipherSuite
        include_relationships = True

    ciphersuite = Nested(CipherSuiteSchema)
    handshake_error_message = Pluck("RejectedCipherHandshakeErrorMessageSchema", "handshake_error_message")


class AcceptedCipherSuiteSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.AcceptedCipherSuite
        include_relationships = True

    ciphersuite = Nested(CipherSuiteSchema)
    post_handshake_response = Pluck("AcceptedCipherPostHandshakeResponseSchema", "post_handshake_response")


class TLS13EarlyDataSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.TLS13EarlyData


class SessionRenegotiationSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.SessionRenegotiation


class DeflateCompressionSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.DeflateCompression


class OpenSSLHeartbleedSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.OpenSSLHeartbleed


class OpenSSLCCSInjectionSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.OpenSSLCCSInjection


class DowngradeAttackSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.DowngradeAttack


class ROBOTAttackSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.ROBOTAttack


class TLS12SessionResumptionRateSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.TLS12SessionResumptionRate


class TLS12SessionResumptionSupportSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.TLS12SessionResumptionSupport


class CertificateChainSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.CertificateChain

    verified_certificate_chain = fields.Method("get_chain")

    @staticmethod
    def get_chain(obj):
        return get_array_reschemed(app.db_models.Certificate, CertificateSchema, obj.chain)


class HTTPSecurityHeadersSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.HTTPSecurityHeaders

        include_relationships = True

    verified_certificate_chain_list = Nested(CertificateChainSchema)


class OCSPResponseSingleSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.OCSPResponseSingle


class OCSPResponseSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.OCSPResponse

    responses_list = fields.Method("get_responses")

    @staticmethod
    def get_responses(obj):
        return get_array_reschemed(app.db_models.OCSPResponseSingle, OCSPResponseSingleSchema, obj.responses_list)


class CertificateInformationSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.CertificateInformation
        include_relationships = True

    ocsp_response = Nested(OCSPResponseSchema)
    received_certificate_chain_list = Nested(CertificateChainSchema)
    verified_certificate_chain_list = Nested(CertificateChainSchema)

    path_validation_result_list = fields.Method("get_validation_result")
    path_validation_error_list = fields.Method("get_validation_error")

    @staticmethod
    def get_validation_result(obj):
        return get_array_reschemed(app.db_models.ValidatedPath, ValidatedPathScheme, obj.path_validation_result_list)

    @staticmethod
    def get_validation_error(obj):
        return get_array_reschemed(app.db_models.ValidatedPath, ValidatedPathScheme, obj.path_validation_error_list)


class ValidatedPathScheme(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.ValidatedPath
        include_relationships = True

    trust_store = Nested(TrustStoreSchema)
    chain = Nested(CertificateChainSchema)


class CipherSuiteScanResultSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.CipherSuiteScanResult
        include_relationships = True

    preferred_cipher = Nested(AcceptedCipherSuiteSchema)

    accepted_cipher_list = fields.Method("get_accepted")
    rejected_cipher_list = fields.Method("get_rejected")
    errored_cipher_list = fields.Method("get_errored")

    @staticmethod
    def get_accepted(obj):
        return get_array_reschemed(app.db_models.AcceptedCipherSuite, AcceptedCipherSuiteSchema,
                                   obj.accepted_cipher_list)

    @staticmethod
    def get_rejected(obj):
        return get_array_reschemed(app.db_models.RejectedCipherSuite, RejectedCipherSuiteSchema,
                                   obj.rejected_cipher_list)

    @staticmethod
    def get_errored(obj):
        return get_array_reschemed(app.db_models.CipherSuite, CipherSuiteSchema,
                                   obj.errored_cipher_list)  # todo: check ErroredCipherSuite


class ScanResultsSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.ScanResults
        include_relationships = True

    server_info = Nested(ServerInfoSchema)
    deflate_compression = Nested(DeflateCompressionSchema)
    session_renegotiation = Nested(SessionRenegotiationSchema)
    tls_13_early_data = Nested(TLS13EarlyDataSchema)
    openssl_ccs_injection = Nested(OpenSSLCCSInjectionSchema)
    openssl_heartbleed = Nested(OpenSSLHeartbleedSchema)
    downgrade_attacks = Nested(DowngradeAttackSchema)
    robot_attack = Nested(ROBOTAttackSchema)
    tls_12_session_resumption_rate = Nested(TLS12SessionResumptionRateSchema)
    tls_12_session_resumption_support = Nested(TLS12SessionResumptionSupportSchema)
    http_security_headers = Nested(HTTPSecurityHeadersSchema)
    certificate_information = Nested(CertificateInformationSchema)
    sslv2 = Nested(CipherSuiteScanResultSchema)
    sslv3 = Nested(CipherSuiteScanResultSchema)
    tlsv1 = Nested(CipherSuiteScanResultSchema)
    tlsv11 = Nested(CipherSuiteScanResultSchema)
    tlsv12 = Nested(CipherSuiteScanResultSchema)
    tlsv13 = Nested(CipherSuiteScanResultSchema)


# Notifications
class NotificationsSchema(SQLAlchemyAutoSchema):
    class Meta(BaseSchema.Meta):
        model = app.db_models.Notifications
        include_relationships = True
        include_fk = True  # this needs to be enabled for schema.load to work properly

    target = Nested(TargetSchema)
    user = Nested(UserSchema)