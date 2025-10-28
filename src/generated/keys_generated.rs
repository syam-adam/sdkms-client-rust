/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct SobjectRequest {
    #[serde(default)]
    pub activation_date: Option<Time>,
    #[serde(default)]
    pub custom_metadata: Option<HashMap<String, String>>,
    #[serde(default)]
    pub deactivation_date: Option<Time>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub deterministic_signatures: Option<bool>,
    #[serde(default)]
    pub elliptic_curve: Option<EllipticCurve>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub fpe: Option<FpeOptions>,
    #[serde(default)]
    pub key_ops: Option<KeyOperations>,
    #[serde(default)]
    pub key_size: Option<u32>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub obj_type: Option<ObjectType>,
    #[serde(default)]
    pub pub_exponent: Option<u32>,
    #[serde(default)]
    pub publish_public_key: Option<PublishPublicKeyConfig>,
    #[serde(default)]
    pub rsa: Option<RsaOptions>,
    #[serde(default)]
    pub state: Option<SobjectState>,
    #[serde(default)]
    pub transient: Option<bool>,
    #[serde(default)]
    pub value: Option<Blob>,
    #[serde(default)]
    pub group_id: Option<Uuid>,
}

/// Request to compute digest of a key.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct ObjectDigestRequest {
    pub key: SobjectDescriptor,
    pub alg: DigestAlgorithm,
}

/// Digest of a key.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct ObjectDigestResponse {
    #[serde(default)]
    pub kid: Option<Uuid>,
    pub digest: Blob,
}

/// Request to persist a transient key.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct PersistTransientKeyRequest {
    #[serde(default)]
    pub activation_date: Option<Time>,
    #[serde(default)]
    pub deactivation_date: Option<Time>,
    /// Name of the persisted security object. Security object names must be unique within an account.
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// User-defined metadata for the persisted key stored as key-value pairs.
    #[serde(default)]
    pub custom_metadata: Option<HashMap<String, String>>,
    /// Whether the new security object should be enabled. Disabled security objects may not perform cryptographic operations.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Group ID of the security group that the persisted key should belong to. The user or
    /// application creating this security object must be a member of this group. If no group is
    /// specified, the default group for the requesting application will be used.
    #[serde(default)]
    pub group_id: Option<Uuid>,
    #[serde(default)]
    pub state: Option<SobjectState>,
    /// Transient key to persist.
    pub transient_key: Blob,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ListSobjectsParams {
    pub group_id: Option<Uuid>,
    pub creator: Option<Uuid>,
    pub name: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    #[serde(flatten)]
    pub sort: SobjectSort,
    /// Allows filtering Sobjects based on various attributes, including kid, key_size, and more.
    /// The support portal section [2.8.1 Filtering Security Objects Using DSM REST API](https://support.fortanix.com/docs/users-guide-fortanix-data-security-manager-key-lifecycle-management#281-filtering-security-objects-using-dsm-rest-api) explains how to
    /// compose various queries using the supported filter operations.
    ///
    /// The following examples illustrate how to apply these filters when listing security objects:
    /// - `filter: {"kid":{"$text":{"$search":"1e70c17a-78c3-4fd9-83f5-dbea8641147a"}}}`
    /// - `filter: {"name":{"$text":{"$search":"13F977EE2B857998"}}}`
    /// - `filter: {"state":{"$eq":"Deactivated"}}`
    /// - `filter: {"key_ops":{"$any":{"$or":[{"$eq":"ENCRYPT"},{"$eq":"DECRYPT"},{"$eq":"WRAPKEY"},{"$eq":"UNWRAPKEY"}]}}}`
    /// - `filter: {"group_name":{"$text":{"$search":"Test_Group"}}}`
    /// - `filter: {"creator_name":{"$text":{"$search":"key creator"}}}`
    /// - `filter: {"$and":[{"creator_type":{"$in":["App","User","Plugin"]}},{"obj_type":{"$eq":"RSA"}}, {"enabled":{"$eq":"false"}}]}`
    /// - `filter: {"$and":[{"key_size":{"$gte":256}},{"obj_type":{"$eq":"AES"}}]}`
    /// - `filter: {"custom_attributes.custom":{"$text":{"$search":"1"}}}`
    /// - `filter: {"created_at":{"$lt":1739794080}}`
    /// - `filter: {"key_ops":{"$all":{"$ne":"HIGHVOLUME"}}}`
    /// - `filter: {"description":{"$text":{"$search":"BIPS32"}}}`
    /// - `filter: {"$and": [{"expires":{"$lt":1739794200}},{"expires":{"$gte":1741001700}},{"obj_type":{"$nin":["OPAQUE","SECRET"]}},{"creator_type":{"$eq":"App"}}]}`
    /// - `filter: {"$and":[{"obj_type":{"$eq":"AES"}},{"obj_type":{"$nin":["DES3","HMAC"]}},{"expires":{"$lt":1739794200}},{"state":{"$nin":["Compromise","Destroyed"]}}]}`
    /// - `filter: {"$and": [{"key_size": 256}, {"state":{"$eq":"Deactivated"}}, {"name":{"$text":{"$search":"13F977EE2B857998"}}}]`
    /// - `filter: {"$and":[{"obj_type":{"$in":["AES","DES3"]}},{"creator_type":{"$eq":"User"}}, {"state":{"$ne":"Compromised"}}, {"creator_id":{"$text":{"$search":"542c9eeb-333c-4b30-b0c6-b73260866cfb"}}}]}`
    /// - `filter: {"wrapping_key":{"$text":{"$search":"3acc3178-b1df-42e9-83c1-0c667119a132"}}}`
    /// - `filter: {"group_id":{"$text":{"$search":"fde289c5-55bd-48d5-b9b9-2fb2dc14388f"}}}`
    /// - `filter: {"creator_id":{"$text":{"$search":"542c9eeb-333c-4b30-b0c6-b73260866cfb"}}}`
    /// - `filter: {"enabled":{"$eq":"true"}}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>
}

impl UrlEncode for ListSobjectsParams {
    fn url_encode(&self, m: &mut HashMap<&'static str, String>) {
        if let Some(ref v) = self.group_id {
            m.insert("group_id", v.to_string());
        }
        if let Some(ref v) = self.creator {
            m.insert("creator", v.to_string());
        }
        if let Some(ref v) = self.name {
            m.insert("name", v.to_string());
        }
        if let Some(ref v) = self.limit {
            m.insert("limit", v.to_string());
        }
        if let Some(ref v) = self.offset {
            m.insert("offset", v.to_string());
        }
        self.sort.url_encode(m);
        if let Some(ref v) = self.filter {
            m.insert("filter".to_string(), v.to_string());
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct GetSobjectParams {
    pub view: SobjectEncoding,
}

impl UrlEncode for GetSobjectParams {
    fn url_encode(&self, m: &mut HashMap<&'static str, String>) {
        m.insert("view", self.view.to_string());
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SobjectEncoding {
    Json,
    Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SobjectSort {
    ByKid { order: Order, start: Option<Uuid> },
    ByName { order: Order, start: Option<String> },
}

impl UrlEncode for SobjectSort {
    fn url_encode(&self, m: &mut HashMap<&'static str, String>) {
        match *self {
            SobjectSort::ByKid {
                ref order,
                ref start,
            } => {
                m.insert("sort", format!("kid:{}", order));
                if let Some(v) = start {
                    m.insert("start", v.to_string());
                }
            }
            SobjectSort::ByName {
                ref order,
                ref start,
            } => {
                m.insert("sort", format!("name:{}", order));
                if let Some(v) = start {
                    m.insert("start", v.to_string());
                }
            }
        }
    }
}

pub struct OperationCreateSobject;
#[allow(unused)]
impl Operation for OperationCreateSobject {
    type PathParams = ();
    type QueryParams = ();
    type Body = SobjectRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys")
    }
}

impl SdkmsClient {
    pub fn create_sobject(&self, req: &SobjectRequest) -> Result<Sobject> {
        self.execute::<OperationCreateSobject>(req, (), None)
    }
}

pub struct OperationImportSobject;
#[allow(unused)]
impl Operation for OperationImportSobject {
    type PathParams = ();
    type QueryParams = ();
    type Body = SobjectRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::PUT
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys")
    }
}

impl SdkmsClient {
    pub fn import_sobject(&self, req: &SobjectRequest) -> Result<Sobject> {
        self.execute::<OperationImportSobject>(req, (), None)
    }
}

pub struct OperationUpdateSobject;
#[allow(unused)]
impl Operation for OperationUpdateSobject {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = SobjectRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::PATCH
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/{id}", id = p.0)
    }
}

impl SdkmsClient {
    pub fn update_sobject(&self, id: &Uuid, req: &SobjectRequest) -> Result<Sobject> {
        self.execute::<OperationUpdateSobject>(req, (id,), None)
    }
    pub fn request_approval_to_update_sobject(
        &self,
        id: &Uuid,
        req: &SobjectRequest,
        description: Option<String>,
    ) -> Result<PendingApproval<OperationUpdateSobject>> {
        self.request_approval::<OperationUpdateSobject>(req, (id,), None, description)
    }
}

pub struct OperationDeleteSobject;
#[allow(unused)]
impl Operation for OperationDeleteSobject {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::DELETE
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/{id}", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> {
        None
    }
}

impl SdkmsClient {
    pub fn delete_sobject(&self, id: &Uuid) -> Result<()> {
        self.execute::<OperationDeleteSobject>(&(), (id,), None)
    }
    pub fn request_approval_to_delete_sobject(
        &self,
        id: &Uuid,
        description: Option<String>,
    ) -> Result<PendingApproval<OperationDeleteSobject>> {
        self.request_approval::<OperationDeleteSobject>(&(), (id,), None, description)
    }
}

pub struct OperationListSobjects;
#[allow(unused)]
impl Operation for OperationListSobjects {
    type PathParams = ();
    type QueryParams = ListSobjectsParams;
    type Body = ();
    type Output = Vec<Sobject>;

    fn method() -> Method {
        Method::GET
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys?{q}", q = q.encode())
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> {
        None
    }
}

impl SdkmsClient {
    pub fn list_sobjects(&self, query_params: Option<&ListSobjectsParams>) -> Result<Vec<Sobject>> {
        self.execute::<OperationListSobjects>(&(), (), query_params)
    }
}

pub struct OperationGetSobject;
#[allow(unused)]
impl Operation for OperationGetSobject {
    type PathParams = ();
    type QueryParams = GetSobjectParams;
    type Body = SobjectDescriptor;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/info?{q}", q = q.encode())
    }
}

impl SdkmsClient {
    pub fn get_sobject(
        &self,
        query_params: Option<&GetSobjectParams>,
        req: &SobjectDescriptor,
    ) -> Result<Sobject> {
        self.execute::<OperationGetSobject>(req, (), query_params)
    }
}

pub struct OperationRemovePrivate;
#[allow(unused)]
impl Operation for OperationRemovePrivate {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::DELETE
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/{id}/private", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> {
        None
    }
}

impl SdkmsClient {
    pub fn remove_private(&self, id: &Uuid) -> Result<()> {
        self.execute::<OperationRemovePrivate>(&(), (id,), None)
    }
}

pub struct OperationExportSobject;
#[allow(unused)]
impl Operation for OperationExportSobject {
    type PathParams = ();
    type QueryParams = ();
    type Body = SobjectDescriptor;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/export")
    }
}

impl SdkmsClient {
    pub fn export_sobject(&self, req: &SobjectDescriptor) -> Result<Sobject> {
        self.execute::<OperationExportSobject>(req, (), None)
    }
    pub fn request_approval_to_export_sobject(
        &self,
        req: &SobjectDescriptor,
        description: Option<String>,
    ) -> Result<PendingApproval<OperationExportSobject>> {
        self.request_approval::<OperationExportSobject>(req, (), None, description)
    }
}

pub struct OperationDigestSobject;
#[allow(unused)]
impl Operation for OperationDigestSobject {
    type PathParams = ();
    type QueryParams = ();
    type Body = ObjectDigestRequest;
    type Output = ObjectDigestResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/digest")
    }
}

impl SdkmsClient {
    pub fn digest_sobject(&self, req: &ObjectDigestRequest) -> Result<ObjectDigestResponse> {
        self.execute::<OperationDigestSobject>(req, (), None)
    }
}

pub struct OperationPersistTransientKey;
#[allow(unused)]
impl Operation for OperationPersistTransientKey {
    type PathParams = ();
    type QueryParams = ();
    type Body = PersistTransientKeyRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/persist")
    }
}

impl SdkmsClient {
    pub fn persist_transient_key(&self, req: &PersistTransientKeyRequest) -> Result<Sobject> {
        self.execute::<OperationPersistTransientKey>(req, (), None)
    }
}

pub struct OperationRotateSobject;
#[allow(unused)]
impl Operation for OperationRotateSobject {
    type PathParams = ();
    type QueryParams = ();
    type Body = SobjectRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/rekey")
    }
}

impl SdkmsClient {
    pub fn rotate_sobject(&self, req: &SobjectRequest) -> Result<Sobject> {
        self.execute::<OperationRotateSobject>(req, (), None)
    }
}

pub struct OperationActivateSobject;
#[allow(unused)]
impl Operation for OperationActivateSobject {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/{id}/activate", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> {
        None
    }
}

impl SdkmsClient {
    pub fn activate_sobject(&self, id: &Uuid) -> Result<()> {
        self.execute::<OperationActivateSobject>(&(), (id,), None)
    }
}

pub struct OperationRevokeSobject;
#[allow(unused)]
impl Operation for OperationRevokeSobject {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = RevocationReason;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/{id}/revoke", id = p.0)
    }
}

impl SdkmsClient {
    pub fn revoke_sobject(&self, id: &Uuid, req: &RevocationReason) -> Result<()> {
        self.execute::<OperationRevokeSobject>(req, (id,), None)
    }
}

pub struct OperationBatchSign;
#[allow(unused)]
impl Operation for OperationBatchSign {
    type PathParams = ();
    type QueryParams = ();
    type Body = Vec<SignRequest>;
    type Output = Vec<BatchResponseItem<SignResponse>>;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/batch/sign")
    }
}

impl SdkmsClient {
    pub fn batch_sign(
        &self,
        req: &Vec<SignRequest>,
    ) -> Result<Vec<BatchResponseItem<SignResponse>>> {
        self.execute::<OperationBatchSign>(req, (), None)
    }
    pub fn request_approval_to_batch_sign(
        &self,
        req: &Vec<SignRequest>,
        description: Option<String>,
    ) -> Result<PendingApproval<OperationBatchSign>> {
        self.request_approval::<OperationBatchSign>(req, (), None, description)
    }
}

pub struct OperationBatchVerify;
#[allow(unused)]
impl Operation for OperationBatchVerify {
    type PathParams = ();
    type QueryParams = ();
    type Body = Vec<VerifyRequest>;
    type Output = Vec<BatchResponseItem<VerifyResponse>>;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/keys/batch/verify")
    }
}

impl SdkmsClient {
    pub fn batch_verify(
        &self,
        req: &Vec<VerifyRequest>,
    ) -> Result<Vec<BatchResponseItem<VerifyResponse>>> {
        self.execute::<OperationBatchVerify>(req, (), None)
    }
}
