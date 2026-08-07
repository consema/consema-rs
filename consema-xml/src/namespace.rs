//! Namespace-aware expanded names and immutable binding scope (RFC 0012 §5).
//!
//! Prefix spelling is source representation. Expanded-name equality compares
//! the namespace URI and the local name, never the prefix. Resolution follows
//! Namespaces in XML 1.0 Third Edition without URI fetch or normalization.

use std::sync::Arc;

/// Standard URI permanently bound to the `xml` prefix.
pub const XML_NAMESPACE_URI: &str = "http://www.w3.org/XML/1998/namespace";

/// URI of the reserved `xmlns` prefix.
pub const XMLNS_NAMESPACE_URI: &str = "http://www.w3.org/2000/xmlns/";

/// One lexical QName with its source-derived parts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QName {
    /// Prefix spelling before the colon, when present.
    pub prefix: Option<Arc<str>>,
    /// Local name after the colon, or the whole name when unprefixed.
    pub local: Arc<str>,
}

impl QName {
    /// Creates a QName from an already split prefix and local name.
    #[must_use]
    pub fn new(prefix: Option<Arc<str>>, local: Arc<str>) -> Self {
        Self { prefix, local }
    }

    /// Full lexical spelling `prefix:local` or `local`.
    #[must_use]
    pub fn as_str(&self) -> String {
        match &self.prefix {
            Some(prefix) => format!("{prefix}:{}", self.local),
            None => self.local.to_string(),
        }
    }
}

/// Resolved expanded name = `{ namespace URI or none, local name }`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExpandedName {
    /// Namespace URI, or `None` for an unprefixed attribute or an unbound
    /// default namespace.
    pub namespace: Option<Arc<str>>,
    /// Local name.
    pub local: Arc<str>,
}

impl ExpandedName {
    /// Creates an expanded name.
    #[must_use]
    pub fn new(namespace: Option<Arc<str>>, local: Arc<str>) -> Self {
        Self { namespace, local }
    }
}

/// One in-scope namespace binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Bound prefix; `None` is the default namespace.
    pub prefix: Option<Arc<str>>,
    /// Namespace URI.
    pub uri: Arc<str>,
}

/// Namespace resolution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespaceError {
    /// A prefixed name has no in-scope binding.
    UnboundPrefix {
        /// The unbound prefix spelling.
        prefix: Arc<str>,
    },
    /// `xmlns` or another reserved prefix was used as an ordinary name or a
    /// declaration prefix.
    ReservedPrefix {
        /// The reserved prefix spelling.
        prefix: Arc<str>,
    },
    /// The `xml` prefix was declared to a non-standard URI.
    IllegalXmlRebinding {
        /// The rejected URI.
        uri: Arc<str>,
    },
    /// The `xmlns` URI was bound as the default namespace.
    IllegalDefaultXmlns,
}

/// Immutable, ancestry-derived namespace scope.
///
/// A scope is never mutated in place. Declaring a binding appends to a new
/// child scope, so the immutable ancestry chain of a tree is preserved.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NamespaceScope {
    /// Most-recent binding first; a `None` prefix is the default namespace.
    bindings: Vec<Binding>,
}

impl NamespaceScope {
    /// Creates an empty scope holding only the permanent `xml` binding rule.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    /// All in-scope bindings in declaration order; a `None` prefix is the
    /// default namespace.
    #[must_use]
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// Appends one namespace declaration and returns the child scope.
    ///
    /// The `xmlns` prefix can never be declared, the `xml` prefix can only be
    /// declared to its standard URI, and the `xmlns` URI cannot become the
    /// default namespace.
    pub fn declare(
        &self,
        prefix: Option<Arc<str>>,
        uri: Arc<str>,
    ) -> Result<NamespaceScope, NamespaceError> {
        if uri.as_ref() == XMLNS_NAMESPACE_URI && prefix.is_none() {
            return Err(NamespaceError::IllegalDefaultXmlns);
        }
        if let Some(prefix) = &prefix {
            if prefix.as_ref() == "xmlns" {
                return Err(NamespaceError::ReservedPrefix {
                    prefix: Arc::clone(prefix),
                });
            }
            if prefix.as_ref() == "xml" && uri.as_ref() != XML_NAMESPACE_URI {
                return Err(NamespaceError::IllegalXmlRebinding { uri });
            }
        }
        let mut bindings = Vec::with_capacity(self.bindings.len() + 1);
        bindings.extend_from_slice(&self.bindings);
        bindings.push(Binding { prefix, uri });
        Ok(Self { bindings })
    }

    /// Resolves an element name: the default namespace applies.
    pub fn resolve_element(&self, qname: &QName) -> Result<ExpandedName, NamespaceError> {
        match &qname.prefix {
            None => Ok(ExpandedName {
                namespace: self.lookup_default(),
                local: Arc::clone(&qname.local),
            }),
            Some(prefix) => self.resolve_prefixed(qname, prefix),
        }
    }

    /// Resolves an attribute name: the default namespace never applies.
    pub fn resolve_attribute(&self, qname: &QName) -> Result<ExpandedName, NamespaceError> {
        match &qname.prefix {
            None => Ok(ExpandedName {
                namespace: None,
                local: Arc::clone(&qname.local),
            }),
            Some(prefix) => self.resolve_prefixed(qname, prefix),
        }
    }

    /// Expanded name of a namespace declaration attribute itself.
    ///
    /// `xmlns` is `{ xmlns-URI, "xmlns" }` and `xmlns:p` is
    /// `{ xmlns-URI, "p" }`, used for attribute-uniqueness checks.
    #[must_use]
    pub fn declaration_expanded_name(prefix: Option<&str>) -> ExpandedName {
        let local: Arc<str> = prefix.unwrap_or("xmlns").into();
        ExpandedName {
            namespace: Some(Arc::from(XMLNS_NAMESPACE_URI)),
            local,
        }
    }

    fn lookup_default(&self) -> Option<Arc<str>> {
        self.bindings
            .iter()
            .rev()
            .find(|binding| binding.prefix.is_none())
            .map(|binding| Arc::clone(&binding.uri))
    }

    fn resolve_prefixed(
        &self,
        qname: &QName,
        prefix: &Arc<str>,
    ) -> Result<ExpandedName, NamespaceError> {
        if prefix.as_ref() == "xml" {
            return Ok(ExpandedName {
                namespace: Some(Arc::from(XML_NAMESPACE_URI)),
                local: Arc::clone(&qname.local),
            });
        }
        if prefix.as_ref() == "xmlns" {
            return Err(NamespaceError::ReservedPrefix {
                prefix: Arc::clone(prefix),
            });
        }
        let uri = self
            .bindings
            .iter()
            .rev()
            .find(|binding| binding.prefix.as_deref() == Some(prefix.as_ref()))
            .map(|binding| Arc::clone(&binding.uri))
            .ok_or_else(|| NamespaceError::UnboundPrefix {
                prefix: Arc::clone(prefix),
            })?;
        Ok(ExpandedName {
            namespace: Some(uri),
            local: Arc::clone(&qname.local),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qn(prefix: Option<&str>, local: &str) -> QName {
        QName {
            prefix: prefix.map(Arc::from),
            local: Arc::from(local),
        }
    }

    fn uri(value: &str) -> Arc<str> {
        Arc::from(value)
    }

    #[test]
    fn default_namespace_applies_to_elements_not_attributes() {
        let scope = NamespaceScope::new()
            .declare(None, uri("urn:app"))
            .expect("default declaration");
        let element = scope
            .resolve_element(&qn(None, "service"))
            .expect("element resolves through default namespace");
        assert_eq!(element.namespace.as_deref(), Some("urn:app"));
        let attribute = scope
            .resolve_attribute(&qn(None, "name"))
            .expect("unprefixed attribute resolves");
        assert_eq!(attribute.namespace, None);
        assert_eq!(attribute.local.as_ref(), "name");
    }

    #[test]
    fn prefixed_name_requires_in_scope_binding() {
        let scope = NamespaceScope::new();
        let error = scope
            .resolve_element(&qn(Some("svc"), "service"))
            .expect_err("unbound prefix must fail");
        assert_eq!(
            error,
            NamespaceError::UnboundPrefix {
                prefix: Arc::from("svc"),
            }
        );
    }

    #[test]
    fn xml_prefix_is_permanently_bound() {
        let scope = NamespaceScope::new();
        let expanded = scope
            .resolve_element(&qn(Some("xml"), "lang"))
            .expect("xml prefix resolves without declaration");
        assert_eq!(expanded.namespace.as_deref(), Some(XML_NAMESPACE_URI));
        assert_eq!(expanded.local.as_ref(), "lang");
    }

    #[test]
    fn xml_prefix_cannot_be_rebound() {
        let scope = NamespaceScope::new();
        let error = scope
            .declare(Some(Arc::from("xml")), uri("urn:wrong"))
            .expect_err("xml rebinding must fail");
        assert!(matches!(error, NamespaceError::IllegalXmlRebinding { .. }));
        let declared = scope
            .declare(Some(Arc::from("xml")), uri(XML_NAMESPACE_URI))
            .expect("declaring xml to its standard URI is legal");
        let expanded = declared
            .resolve_element(&qn(Some("xml"), "lang"))
            .expect("still resolves");
        assert_eq!(expanded.namespace.as_deref(), Some(XML_NAMESPACE_URI));
    }

    #[test]
    fn xmlns_prefix_is_reserved_everywhere() {
        let scope = NamespaceScope::new();
        let error = scope
            .resolve_element(&qn(Some("xmlns"), "x"))
            .expect_err("xmlns must not be an ordinary prefix");
        assert!(matches!(error, NamespaceError::ReservedPrefix { .. }));
        let error = scope
            .declare(Some(Arc::from("xmlns")), uri("urn:x"))
            .expect_err("xmlns must not be declared");
        assert!(matches!(error, NamespaceError::ReservedPrefix { .. }));
        let error = scope
            .declare(None, uri(XMLNS_NAMESPACE_URI))
            .expect_err("xmlns URI must not become the default namespace");
        assert_eq!(error, NamespaceError::IllegalDefaultXmlns);
    }

    #[test]
    fn child_scope_shadows_parent_binding() {
        let parent = NamespaceScope::new()
            .declare(Some(Arc::from("p")), uri("urn:one"))
            .expect("parent binding");
        let child = parent
            .declare(Some(Arc::from("p")), uri("urn:two"))
            .expect("child rebinding");
        let parent_name = parent
            .resolve_element(&qn(Some("p"), "x"))
            .expect("parent scope resolves");
        let child_name = child
            .resolve_element(&qn(Some("p"), "x"))
            .expect("child scope resolves");
        assert_eq!(parent_name.namespace.as_deref(), Some("urn:one"));
        assert_eq!(child_name.namespace.as_deref(), Some("urn:two"));
        assert_ne!(parent_name, child_name);
    }

    #[test]
    fn equality_ignores_prefix_spelling() {
        let a = NamespaceScope::new()
            .declare(Some(Arc::from("a")), uri("urn:same"))
            .and_then(|scope| scope.resolve_element(&qn(Some("a"), "item")))
            .expect("resolve a");
        let b = NamespaceScope::new()
            .declare(Some(Arc::from("b")), uri("urn:same"))
            .and_then(|scope| scope.resolve_element(&qn(Some("b"), "item")))
            .expect("resolve b");
        assert_eq!(a, b);
        let c = NamespaceScope::new()
            .declare(Some(Arc::from("a")), uri("urn:other"))
            .and_then(|scope| scope.resolve_element(&qn(Some("a"), "item")))
            .expect("resolve c");
        assert_ne!(a, c);
    }

    #[test]
    fn declaration_attributes_get_the_xmlns_namespace() {
        let default = NamespaceScope::declaration_expanded_name(None);
        assert_eq!(default.namespace.as_deref(), Some(XMLNS_NAMESPACE_URI));
        assert_eq!(default.local.as_ref(), "xmlns");
        let prefixed = NamespaceScope::declaration_expanded_name(Some("p"));
        assert_eq!(prefixed.namespace.as_deref(), Some(XMLNS_NAMESPACE_URI));
        assert_eq!(prefixed.local.as_ref(), "p");
    }

    #[test]
    fn unprefixed_attributes_never_see_the_default_namespace() {
        let scope = NamespaceScope::new()
            .declare(None, uri("urn:app"))
            .expect("default declaration");
        let expanded = scope
            .resolve_attribute(&qn(None, "version"))
            .expect("attribute resolves");
        assert_eq!(
            expanded,
            ExpandedName {
                namespace: None,
                local: Arc::from("version"),
            }
        );
    }
}
