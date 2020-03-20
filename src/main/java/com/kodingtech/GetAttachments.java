package com.kodingtech;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.*;

import com.microsoft.azure.functions.annotation.*;
import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.xfa.XfaForm;
import com.itextpdf.text.exceptions.UnsupportedPdfException;
import com.itextpdf.text.pdf.PRStream;
import com.itextpdf.text.pdf.PdfObject;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.kodingtech.models.RequestBody;
import com.microsoft.azure.functions.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Azure Functions with HTTP Trigger.
 */
public class GetAttachments {

    /**
     * This function listens at endpoint "/api/GetAttachments". Two ways to invoke it using
     * "curl" command in bash: 1. curl -d "HTTP Body" {your host}/api/FillPdf 2.
     * curl {your host}/api/FillPdf?name=HTTP%20Query
     */
    @FunctionName("fillPdf")
    public HttpResponseMessage run(@HttpTrigger(name = "req", methods = {
            HttpMethod.POST }, authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<RequestBody>> request,
            final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

        // Parse query parameter
        boolean hasBody = request.getBody().isPresent();
        if (!hasBody) {
            return Utils.badRequest(request, 1, "No request body was found. Please provide a request body.");
        }

        RequestBody body = request.getBody().get();
        String base64pdf = body.getPdf();

        if (base64pdf == null) {
            return Utils.badRequest(request, 100,
                    "No PDF field was found in the request body. Please provide a base64-encoded PDF file.");
        }

        try {
            
            byte[] decodedPdfBytes = Base64.getDecoder().decode(base64pdf);
        
            ByteArrayInputStream pdfStream = new ByteArrayInputStream(decodedPdfBytes);
            ByteArrayOutputStream pdfOutputStream = new ByteArrayOutputStream();

            PdfReader reader = new PdfReader(pdfStream);
            PdfObject obj;
            PdfDocument doc = new PdfDocument(reader);
            byte[] byteArray;
            for (int i = 1; i <= pdfDoc.getNumberOfPdfObjects(); i++) {
                obj = pdfDoc.getPdfObject(i);
                if (obj != null && obj.isStream()) {
                    
                    try {
                        byteArray = ((PdfStream) obj).getBytes();
                    } catch (PdfException exc) {
                        byteArray = ((PdfStream) obj).getBytes(false);
                    }
                    
                }
            }
            xfa.fillXfaForm(xmlStream);
            xfa.write(doc);

            doc.close();
            reader.close();

            byte[] encodedAttachmentBytes = Base64.getEncoder().encode(byteArray);
            String encodedAttachments = new String(encodedPdfBytes);

            return request.createResponseBuilder(HttpStatus.OK).body(encodedAttachments).build();

        } catch (IOException e) {
            context.getLogger().severe("Failed reading decoded PDF with the following base64: " + base64pdf);
            return Utils.badRequest(request, 101,
                    "Failed reading decoded PDF. Please make sure you have supplied a valid PDF.");
        }

    }
}
