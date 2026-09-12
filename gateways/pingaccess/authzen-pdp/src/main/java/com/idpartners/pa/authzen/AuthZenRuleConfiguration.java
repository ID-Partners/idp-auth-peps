package com.idpartners.pa.authzen;

import com.pingidentity.pa.sdk.policy.SimplePluginConfiguration;
import com.pingidentity.pa.sdk.ui.ConfigurationType;
import com.pingidentity.pa.sdk.ui.Help;
import com.pingidentity.pa.sdk.ui.Option;
import com.pingidentity.pa.sdk.ui.UIElement;
import jakarta.validation.constraints.NotBlank;

import java.util.ArrayList;
import java.util.List;

/**
 * The rule's configuration. The field names are the per-route knobs every PEP in this
 * repository takes (Kong plugin config, ext_authz context extensions, the HTTP check
 * API's config object), spelled identically so one map means one thing everywhere; that
 * is why they are snake_case here rather than Java's camelCase. PingAccess binds the
 * rule's JSON configuration to these fields by name.
 *
 * <p>Public fields, as the SDK's own configuration classes have: it is what PingAccess
 * deserialises into.
 */
public class AuthZenRuleConfiguration extends SimplePluginConfiguration {

    @UIElement(order = 10, type = ConfigurationType.TEXT, label = "PDP URL (authzen_url)", required = true,
        help = @Help(title = "The static PDP",
            content = "Base URL of the AuthZEN PDP. Always the fallback and always permitted, whatever discovery finds.", url = ""))
    @NotBlank
    public String authzen_url;

    @UIElement(order = 20, type = ConfigurationType.CONCEALED, label = "PDP API key (authzen_api_key)",
        help = @Help(title = "Bound to the static PDP",
            content = "Sent as a bearer to authzen_url only. A discovered PDP never receives it.", url = ""))
    public String authzen_api_key = "";

    @UIElement(order = 30, type = ConfigurationType.TEXT, label = "PEP label (pep_label)", defaultValue = "pingaccess-pep",
        help = @Help(title = "Who denied", content = "Named in every challenge and in the X-PDP-PEP response header.", url = ""))
    public String pep_label = "pingaccess-pep";

    @UIElement(order = 40, type = ConfigurationType.SELECT, label = "Style (style)", defaultValue = "rest",
        options = {@Option(label = "rest: resource server", value = "rest"), @Option(label = "mcp: MCP edge", value = "mcp")},
        help = @Help(title = "Request mapping", content = "rest maps REST requests to actions and resources; mcp authorises access on the JSON-RPC initialize handshake and delegates tools/call to coaz-pep.", url = ""))
    public String style = "rest";

    @UIElement(order = 50, type = ConfigurationType.CHECKBOX, label = "Require an access token (require_token)", defaultValue = "true")
    public boolean require_token = true;

    @UIElement(order = 60, type = ConfigurationType.CHECKBOX, label = "Require DPoP (require_dpop)", defaultValue = "false",
        help = @Help(title = "Delegated to coaz-pep", content = "Verifies the proof's signature, iat, jti and cnf.jkt/htm/ath binding via coaz_url, which is then required. PingAccess's own DPoP enforcement on the application is the alternative when it validates the token.", url = ""))
    public boolean require_dpop = false;

    @UIElement(order = 70, type = ConfigurationType.CHECKBOX, label = "Require a logged-in user (require_user_login)", defaultValue = "false",
        help = @Help(title = "RFC 9470 login challenge", content = "Deny with a login challenge unless a valid X-User-Token is present.", url = ""))
    public boolean require_user_login = false;

    @UIElement(order = 80, type = ConfigurationType.TEXT, label = "Step-up scope (stepup_scope)",
        help = @Help(title = "Fallback scope", content = "The scope named in a step-up challenge when the PDP's advice names none.", url = ""))
    public String stepup_scope;

    @UIElement(order = 90, type = ConfigurationType.TEXT, label = "Step-up action (stepup_action)", defaultValue = "make_payment", advanced = true)
    public String stepup_action = "make_payment";

    @UIElement(order = 100, type = ConfigurationType.TEXT, label = "coaz-pep check API (coaz_url)",
        help = @Help(title = "The shared engine", content = "Base URL of coaz-pep's HTTP check API. Required for require_dpop; enables per-tool-call authorisation on mcp routes.", url = ""))
    public String coaz_url;

    @UIElement(order = 110, type = ConfigurationType.CONCEALED, label = "coaz-pep API key (coaz_api_key)",
        help = @Help(title = "CHECK_API_TOKEN", content = "The shared secret coaz-pep's check API requires.", url = ""))
    public String coaz_api_key;

    @UIElement(order = 120, type = ConfigurationType.TEXT, label = "MCP upstream (mcp_upstream_url)",
        help = @Help(title = "Where tools/list lives", content = "The MCP server whose tools/list declares the x-authzen-mapping objects, reached by the engine for discovery.", url = ""))
    public String mcp_upstream_url;

    @UIElement(order = 130, type = ConfigurationType.TEXT, label = "Federation entity relay (federation_entity_url)", advanced = true,
        help = @Help(title = "The resource's federation face", content = "coaz-pep's HTTP base when this route is the resource's federation face: the two well-known documents are relayed from it, since PingAccess cannot sign them.", url = ""))
    public String federation_entity_url;

    @UIElement(order = 140, type = ConfigurationType.CHECKBOX, label = "Verify TLS on outbound calls (pdp_ssl_verify)", defaultValue = "true", advanced = true,
        help = @Help(title = "Development only when off", content = "A PEP that silently accepts any certificate has no integrity on the decision it enforces. Off is process-wide for JDK HTTP clients built afterwards.", url = ""))
    public boolean pdp_ssl_verify = true;

    @UIElement(order = 150, type = ConfigurationType.CHECKBOX, label = "COAZ default mappings (coaz_defaults)", defaultValue = "false", advanced = true,
        help = @Help(title = "Conformance", content = "Authorise tools that declare no x-authzen-mapping against the COAZ-MCP binding's default tools/call mapping, as it requires.", url = ""))
    public boolean coaz_defaults = false;

    @UIElement(order = 160, type = ConfigurationType.CHECKBOX, label = "Also send subject.identity (legacy_subject_identity)", defaultValue = "true", advanced = true,
        help = @Help(title = "Migration", content = "Send the non-standard subject.identity beside AuthZEN's subject.id until policies read subject.id.", url = ""))
    public boolean legacy_subject_identity = true;

    @UIElement(order = 170, type = ConfigurationType.SELECT, label = "PDP discovery (pdp_discovery)", defaultValue = "off",
        options = {@Option(label = "off: the static PDP, default paths", value = "off"),
            @Option(label = "authzen: the static PDP's own metadata", value = "authzen"),
            @Option(label = "resource: the resource's RFC 9728 metadata names the PDP", value = "resource")},
        help = @Help(title = "Who decides", content = "No federation mode here: a Trust Chain cannot be validated without coaz-pep. A route that must take the federation's word belongs behind it.", url = ""))
    public String pdp_discovery = "off";

    @UIElement(order = 180, type = ConfigurationType.TEXT, label = "Resource identifier (resource)",
        help = @Help(title = "RFC 8707", content = "The protected resource's identifier, the key discovery starts from. An mcp route without one uses mcp_upstream_url; a rest route without one uses the static PDP.", url = ""))
    public String resource;

    @UIElement(order = 190, type = ConfigurationType.TEXT, label = "Metadata cache TTL, seconds (pdp_metadata_ttl)", defaultValue = "300", advanced = true)
    public int pdp_metadata_ttl = 300;

    @UIElement(order = 200, type = ConfigurationType.LIST, label = "Permitted PDPs (pdp_allowlist)", advanced = true,
        help = @Help(title = "What a resource may name", content = "Prefixes of PDP identifiers a resource may name; authzen_url is always permitted. Empty means any https PDP.", url = ""))
    public List<String> pdp_allowlist = new ArrayList<>();

    @UIElement(order = 210, type = ConfigurationType.LIST, label = "Permitted resources (resource_metadata_allowlist)", advanced = true,
        help = @Help(title = "Whose metadata is fetched", content = "Prefixes of resource identifiers whose metadata may be fetched. Empty means any.", url = ""))
    public List<String> resource_metadata_allowlist = new ArrayList<>();

    @UIElement(order = 220, type = ConfigurationType.CHECKBOX, label = "Allow http for discovered URLs (pdp_discovery_insecure)", defaultValue = "false", advanced = true,
        help = @Help(title = "Development only", content = "authzen_url's own origin is always trusted over http.", url = ""))
    public boolean pdp_discovery_insecure = false;

    @UIElement(order = 230, type = ConfigurationType.CHECKBOX, label = "Forward the raw access token (forward_access_token)", defaultValue = "false",
        help = @Help(title = "context.access_token", content = "Lets the PDP verify and inspect the token itself. Only over a PDP connection that is TLS and authenticated.", url = ""))
    public boolean forward_access_token = false;

    @UIElement(order = 240, type = ConfigurationType.LIST, label = "Policy layers (pdp_layers)",
        help = @Help(title = "Ordered PDPs, every one of which must permit", content = "static, resource, or a PDP identifier, each optionally suffixed ' fail-open' or ' fail-closed'. The first deny is the answer. Default: resource.", url = ""))
    public List<String> pdp_layers = new ArrayList<>(List.of("resource"));

    @UIElement(order = 250, type = ConfigurationType.SELECT, label = "Failure mode (fail_mode)", defaultValue = "closed",
        options = {@Option(label = "closed: an unreachable PDP denies", value = "closed"), @Option(label = "open: an unreachable layer is skipped and the permit marked", value = "open")},
        help = @Help(title = "Outages only", content = "A deny is a decision and a refusal is the PEP's own rule; neither ever opens.", url = ""))
    public String fail_mode = "closed";

    @UIElement(order = 260, type = ConfigurationType.TEXT, label = "X-User-Token JWKS (user_token_jwks_url)",
        help = @Help(title = "Verify the user token", content = "When set, X-User-Token is verified against this JWKS and one that fails yields no claims. Unset, it is decoded only.", url = ""))
    public String user_token_jwks_url;

    @UIElement(order = 270, type = ConfigurationType.TEXT, label = "X-User-Token issuer (user_token_issuer)", advanced = true)
    public String user_token_issuer;

    @UIElement(order = 280, type = ConfigurationType.TEXT, label = "X-User-Token audience (user_token_audience)", advanced = true)
    public String user_token_audience;

    @UIElement(order = 290, type = ConfigurationType.TEXT, label = "PDP timeout, ms (pdp_timeout_ms)", defaultValue = "10000", advanced = true)
    public int pdp_timeout_ms = 10000;

    @UIElement(order = 300, type = ConfigurationType.TEXT, label = "coaz-pep timeout, ms (coaz_timeout_ms)", defaultValue = "15000", advanced = true)
    public int coaz_timeout_ms = 15000;
}
