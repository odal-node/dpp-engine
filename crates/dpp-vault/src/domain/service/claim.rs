//! What a publish claims, and how the other holders of it are found.
//!
//! Publish makes a passport live, and two live passports must not answer for one
//! thing: a GS1 label that names two passports resolves to neither, and an
//! identifier that two passports carry has no single product behind it. Neither
//! can be repaired afterwards, because `supersedesId` is fixed at create.
//!
//! The question is asked at publish, behind a lock, and refused with a field
//! error. This is the one place that says what a passport claims, so the
//! lookup, the lock key and the refusal cannot disagree about it: they did, when
//! each of them knew only the serial, and a passport that prints no serial was
//! checked against nothing.

use dpp_domain::{
    FieldError, ProductIdentifier,
    error::DppError,
    passport::{CarrierQualifier, Passport},
    ports::passport_repo::PassportRepository,
    product_group::ProductGroupData,
};

/// The field a refusal names when what is taken is the identifier itself.
const IDENTIFIER_FIELD: &str = "/productGroupData/productIdentifier";

/// What `passport` claims by going live.
pub(super) enum Claim<'a> {
    /// A GS1 label: the GTIN, and what the carrier prints after it — nothing for
    /// a model, the lot for a batch, the carrier serial otherwise. Passports that
    /// print different things under one GTIN do not collide.
    Label {
        identifier: &'a ProductIdentifier,
        qualifier: CarrierQualifier<'a>,
    },
    /// An identification link or a DID. There is no GTIN to qualify and nothing
    /// printed after it: the value is the whole key.
    ///
    /// Found by the passport's own batch and serial, which is every holder this
    /// node can produce, since it states no serial number and accepts one lot per
    /// passport. A second holder that differs only in its batch is not found
    /// here: that needs a lookup by the whole value, which dpp-core has added
    /// (`find_by_product_identifier`) and its 0.22.0 does not carry.
    Identifier {
        identifier: &'a ProductIdentifier,
        batch: Option<&'a str>,
        serial: Option<&'a str>,
    },
}

impl<'a> Claim<'a> {
    /// What `passport` claims, or `None` when it names no product identifier — or,
    /// for a GS1 passport that states batch level, no lot to print, which
    /// validation refuses before it gets here.
    pub(super) fn of(passport: &'a Passport) -> Option<Self> {
        let identifier = passport
            .product_group_data
            .as_ref()
            .and_then(ProductGroupData::product_identifier)?;
        if identifier.gtin().is_some() {
            Some(Self::Label {
                identifier,
                qualifier: passport.carrier_qualifier()?,
            })
        } else {
            Some(Self::Identifier {
                identifier,
                batch: passport.batch_id.as_deref(),
                serial: passport.serial_number.as_deref(),
            })
        }
    }

    /// Every passport holding what this claims, whatever its status.
    pub(super) async fn holders(
        &self,
        repo: &dyn PassportRepository,
    ) -> Result<Vec<Passport>, DppError> {
        match self {
            Self::Label {
                identifier,
                qualifier,
            } => repo.find_by_carrier(identifier, qualifier).await,
            Self::Identifier {
                identifier,
                batch,
                serial,
            } => repo.find_by_identifier(identifier, *batch, *serial).await,
        }
    }

    /// What the publish lock is keyed on: two claims that can collide have the
    /// same key.
    pub(super) fn key(&self) -> String {
        match self {
            Self::Label {
                identifier,
                qualifier,
            } => format!("{}|{qualifier:?}", identifier.as_str()),
            Self::Identifier {
                identifier,
                batch,
                serial,
            } => format!("{}|{batch:?}|{serial:?}", identifier.as_str()),
        }
    }

    /// The refusal for a claim another published passport already holds.
    pub(super) fn refusal(&self) -> FieldError {
        const WHY: &str = "a label that names two passports resolves to neither. This passport \
                           stays a draft";
        match self {
            Self::Label {
                qualifier: CarrierQualifier::Serial(serial),
                ..
            } => FieldError {
                field: "/carrierSerial".to_owned(),
                message: format!(
                    "{serial:?} is already printed by another published passport under this \
                     GTIN, and {WHY}; create one with another serial, or one that names the \
                     holder in supersedesId."
                ),
            },
            Self::Label {
                identifier,
                qualifier: CarrierQualifier::Batch(lot),
            } => FieldError {
                field: "/batchId".to_owned(),
                message: format!(
                    "{lot:?} is already the lot of another published passport under {}, and \
                     {WHY}; create one under another lot, or one that names the holder in \
                     supersedesId.",
                    identifier.as_str()
                ),
            },
            Self::Label {
                identifier,
                qualifier: CarrierQualifier::Model,
            } => FieldError {
                field: IDENTIFIER_FIELD.to_owned(),
                message: format!(
                    "{} already has a published model-level passport, and {WHY}; name the \
                     holder in supersedesId to replace it.",
                    identifier.as_str()
                ),
            },
            // `CarrierQualifier` is non-exhaustive: a level core adds later is
            // still a label two passports cannot share, so it is refused here
            // rather than waved through by a wildcard that says nothing.
            Self::Label { identifier, .. } => FieldError {
                field: IDENTIFIER_FIELD.to_owned(),
                message: format!(
                    "{} is already printed by another published passport at this level, and \
                     {WHY}; name the holder in supersedesId to replace it.",
                    identifier.as_str()
                ),
            },
            Self::Identifier { identifier, .. } => FieldError {
                field: IDENTIFIER_FIELD.to_owned(),
                message: format!(
                    "{} already identifies another published passport, and an identifier names \
                     one product. This passport stays a draft; name the holder in supersedesId \
                     to replace it.",
                    identifier.as_str()
                ),
            },
        }
    }
}
