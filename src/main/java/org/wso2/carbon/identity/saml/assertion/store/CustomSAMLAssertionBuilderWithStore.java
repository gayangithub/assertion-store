/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.saml.assertion.store;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.sso.saml.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * This class is used to override existing implementation on Assertion building and store Assertions before
 * sending to the requester
 */
public class CustomSAMLAssertionBuilderWithStore extends DefaultSAMLAssertionBuilder implements Serializable {
    /**
     * Standard login
     */
    private final static Log log = LogFactory.getLog(CustomSAMLAssertionBuilderWithStore.class);

    /**
     * This method is used to initialize
     * @throws IdentityException If error occurred
     */
    @Override
    public void init() throws IdentityException {


    }

    /**
     * This method is used to store assertions before sending to the requester
     * @param samlssoAuthnReqDTO Authntication request data object
     * @param notOnOrAfter Assertion expiration time gap
     * @param sessionId Created session id
     * @return Assertion Set of element which contain authentication information
     * @throws IdentityException If unable to collect issuer information
     */
    @Override
    public Assertion buildAssertion(SAMLSSOAuthnReqDTO samlssoAuthnReqDTO, DateTime notOnOrAfter, String sessionId) throws IdentityException {

        Assertion assertion = super.buildAssertion(samlssoAuthnReqDTO, notOnOrAfter, sessionId);


        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            preparedStatement= connection.prepareStatement("INSERT INTO IDN_SAML2_ASSERTION_STORE VALUES (?,?,?,?)");
            preparedStatement.setString(1, assertion.getID());
            preparedStatement.setString(2, assertion.getIssuer().getValue());
            preparedStatement.setString(3, samlssoAuthnReqDTO.getUser().getAuthenticatedSubjectIdentifier());

            String assertionString = SAMLSSOUtil.marshall(assertion);
            preparedStatement.setString(4, assertionString);

            preparedStatement.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            log.error("Error while writing data", e);
        } finally {
            try {
                if(preparedStatement != null){
                    preparedStatement.close();
                }
                if(connection != null){
                    connection.close();
                }
            } catch (SQLException e) {
                log.error("Error while closing the stream", e);
            }
        }

        return  assertion;

    }


}
