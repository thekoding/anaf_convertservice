package com.kodingtech;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.*;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.json.*;

import dec.Validation;
import pdf.PdfCreation;
import pdf.Sign;

import com.microsoft.azure.functions.annotation.*;
import com.kodingtech.models.D300.Declaratie300Type;
import com.microsoft.azure.functions.*;

/**
 * Azure Functions with HTTP Trigger.
 */
public class GenerateD300 {

    /**
     * This function listens at endpoint "/api/generated300". Two ways to invoke it
     * using "curl" command in bash: 1. curl -d "HTTP Body" {your host}/api/FillPdf
     * 2. curl {your host}/api/FillPdf?name=HTTP%20Query
     */
    @FunctionName("generated300")
    public HttpResponseMessage run(@HttpTrigger(name = "req", methods = {
            HttpMethod.POST }, authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<Declaratie300Type>> request,
            final ExecutionContext context) {
        context.getLogger().info("Started generating D300 report.");

        // Parse query parameter0
        boolean hasBody = request.getBody().isPresent();
        if (!hasBody) {
            return Utils.badRequest(request, 1, "No request body was found. Please provide a request body.");
        }

        Declaratie300Type d300 = request.getBody().get();
        String base64key = d300.getKey();
        String keyPassword = d300.getKeyPassword();

        String fileName = Utils.getAlphabeticalString(10);
        String xmlPath = fileName + ".xml";
        String errPath = fileName + ".log";
        String pdfPath = fileName + ".pdf";
        String signedPdfPath = fileName + "s.pdf";

        File xml = new File(xmlPath);
        File errorFile = new File(errPath);
        File pdfFile = new File(pdfPath);
        File signedPdfFile = new File(signedPdfPath);

        try {
            JSONObject returnBody = new JSONObject();

            xml.createNewFile();

            JAXBContext jaxbContext = JAXBContext.newInstance(Declaratie300Type.class);
            Marshaller marshaller = jaxbContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(d300, xml);

            String errorMessage = "";

            Validation validator = new d300validator.Validator();
            PdfCreation creator = new d300.PdfCreator();

            int retCode = validator.parseDocument(xmlPath, errPath);
            String finalPdfPath = null;
            boolean didSign = false;

            if (retCode == -1) {
                Scanner eScanner = new Scanner(errorFile);
                eScanner.useDelimiter("\\Z"); // Read until end of file
                errorMessage += "Validation errors occured. Please check attached logs.\n" + eScanner.next();
                eScanner.close();
            } else if (retCode < 0) {
                Scanner eScanner = new Scanner(errorFile);
                eScanner.useDelimiter("\\Z"); // Read until end of file
                errorMessage += "Validation errors occured. Please check attached logs.\n" + eScanner.next();
                eScanner.close();
            } else {
                creator.createPdf(validator.getInfo(), pdfPath, xmlPath, "");
                finalPdfPath = pdfPath;
            }

            if (finalPdfPath != null) {
                if (base64key != null) {
                    if (keyPassword == null) {
                        return Utils.badRequest(request, 300,
                                "No key password was found in the request body. Please provide a valid password for the keystore.");
                    }
                    byte[] decodedKeyBytes = Base64.getDecoder().decode(base64key);
                    ByteArrayInputStream keyStream = new ByteArrayInputStream(decodedKeyBytes);

                    try {
                        KeyStore keystore = KeyStore.getInstance("PKCS12");

                        keystore.load(keyStream, keyPassword.toCharArray());
                        String alias = keystore.aliases().nextElement();
                        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, keyPassword.toCharArray());
                        privateKey.getAlgorithm();
                        Certificate[] chain = keystore.getCertificateChain(alias);
                        new Sign("signature|-1", null).doSignP12(pdfPath, signedPdfPath, privateKey, chain);
                        finalPdfPath = signedPdfPath;
                        didSign = true;
                    } catch (GeneralSecurityException e) {
                        errorMessage += e.getMessage();
                    }

                }

                File finalPdf = new File(finalPdfPath);
                byte[] finalPdfBytes = new byte[(int) finalPdf.length()];

                FileInputStream stream = new FileInputStream(finalPdfPath);
                stream.read(finalPdfBytes);
                byte[] encodedPdfBytes = Base64.getEncoder().encode(finalPdfBytes);
                String encodedPdf = new String(encodedPdfBytes);
                returnBody.put("base64", encodedPdf);

                stream.close();
            }

            if (xml.exists()) {
                xml.delete();
            }
            if (errorFile.exists()) {
                errorFile.delete();
            }

            if (pdfFile.exists()) {
                pdfFile.delete();
            }

            if (signedPdfFile.exists()) {
                signedPdfFile.delete();
            }

            returnBody.put("signed", didSign);

            if (!errorMessage.isEmpty()) {
                returnBody.put("error", errorMessage);
            }
            return request.createResponseBuilder(HttpStatus.OK).body(returnBody.toString()).build();

        } catch (IOException e) {
            context.getLogger().severe(e.getMessage());
        } catch (JAXBException e) {
            context.getLogger().severe(e.getMessage());
        } finally {
            if (xml.exists()) {
                xml.delete();
            }
            if (errorFile.exists()) {
                errorFile.delete();
            }

            if (pdfFile.exists()) {
                pdfFile.delete();
            }

            if (signedPdfFile.exists()) {
                signedPdfFile.delete();
            }
        }
        return Utils.badRequest(request, 101, "Failed performing the task. Please check the console logs.");

    }
}
