package com.kodingtech;

public class RequestBody {
    private String pdf;

    private String xml;

    private String key;

    private String keyPassword;

    public String getXml() {
        return xml;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getPdf() {
        return pdf;
    }

    public void setPdf(String pdf) {
        this.pdf = pdf;
    }

    public void setXml(String xml) {
        this.xml = xml;
    }
}