//package ptimesso.config;
//
//import lombok.Getter;
//import lombok.RequiredArgsConstructor;
//import lombok.Setter;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class AuthorizationServerProperties {
//
//    @Value("${spring.security.oauth2.authorizationserver}")
//    private String issuerUrl;
//    @Value("${spring.security.oauth2.introspectionEndpoint}")
//    private String introspectionEndpoint;
//
//    public AuthorizationServerProperties() {
//    }
//
//    public String getIssuerUrl() {
//        return issuerUrl;
//    }
//
//    public AuthorizationServerProperties(String issuerUrl, String introspectionEndpoint) {
//        this.issuerUrl = issuerUrl;
//        this.introspectionEndpoint = introspectionEndpoint;
//    }
//
//    public void setIssuerUrl(String issuerUrl) {
//        this.issuerUrl = issuerUrl;
//    }
//
//    public String getIntrospectionEndpoint() {
//        return introspectionEndpoint;
//    }
//
//    public void setIntrospectionEndpoint(String introspectionEndpoint) {
//        this.introspectionEndpoint = introspectionEndpoint;
//    }
//}
