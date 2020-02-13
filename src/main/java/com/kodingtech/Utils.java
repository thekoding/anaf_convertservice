package com.kodingtech;

import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;

import org.json.JSONObject;

public class Utils {
    public static HttpResponseMessage badRequest(HttpRequestMessage<?> request, int code, String message) {
        JSONObject json = new JSONObject();
        json.append("errorCode", code);
        json.append("errorMessge", message);
        return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body(json.toString()).build();
    }

    // function to generate a random string of length n
    // taken from
    // https://www.geeksforgeeks.org/generate-random-string-of-given-size-in-java/
    public static String getAlphabeticalString(int n) {

        // chose a Character random from this String
        String alphabeticalString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvxyz";

        // create StringBuffer size of AlphaNumericString
        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i++) {

            // generate a random number between
            // 0 to AlphaNumericString variable length
            int index = (int) (alphabeticalString.length() * Math.random());

            // add Character one by one in end of sb
            sb.append(alphabeticalString.charAt(index));
        }

        return sb.toString();
    }
}