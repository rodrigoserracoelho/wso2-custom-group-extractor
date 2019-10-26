package eu.europa.ec.digit.apigw.group.extractor;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.apimgt.api.NewPostLoginExecutor;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

@Slf4j
public class ECGroupExtractor implements NewPostLoginExecutor {

    private static final String WSO2_ORGANIZATION_CLAIM = "http://wso2.org/claims/organization";


    public String getGroupingIdentifiers(String loginResponse) {

        String organization = null;
        String username = null;
        try {
            XMLObject samlObject = buildXmlObject(loginResponse);
            Response samlResponse = (Response) samlObject;
            List<Assertion> assertions = samlResponse.getAssertions();

            if (assertions != null && assertions.size() == 1) {
                Subject subject = assertions.get(0).getSubject();
                if (subject != null) {
                    if (subject.getNameID() != null) {
                        username = subject.getNameID().getValue();
                    }
                }
            }
            UserRealm realm = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserRealm();
            UserStoreManager manager = realm.getUserStoreManager();
            organization  = manager.getUserClaimValue(MultitenantUtils.getTenantAwareUsername(username), WSO2_ORGANIZATION_CLAIM, null);
            if (organization != null) {
                organization = organization.trim();
            }
        } catch (UserStoreException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return organization;
    }

    public String[] getGroupingIdentifierList(String loginResponse) {
        String[] organizations = null;
        String username = null;
        try {
            XMLObject samlObject = buildXmlObject(loginResponse);
            Response samlResponse = (Response) samlObject;
            List<Assertion> assertions = samlResponse.getAssertions();

            if (assertions != null && assertions.size() == 1) {
                Subject subject = assertions.get(0).getSubject();
                if (subject != null) {
                    if (subject.getNameID() != null) {
                        username = subject.getNameID().getValue();
                    }
                }
            }
            UserRealm realm = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserRealm();
            UserStoreManager manager = realm.getUserStoreManager();
            String organization  = manager.getUserClaimValue(MultitenantUtils.getTenantAwareUsername(username), WSO2_ORGANIZATION_CLAIM, null);
            if (organization != null) {
                organizations = organization.split(",");
            }
        } catch (UserStoreException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return organizations;
    }

    public XMLObject buildXmlObject(String loginResponse) throws ParserConfigurationException, IOException, SAXException, UnmarshallingException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = docBuilder.parse(new ByteArrayInputStream(loginResponse.trim().getBytes()));
        Element element = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        return unmarshaller.unmarshall(element);
    }
}