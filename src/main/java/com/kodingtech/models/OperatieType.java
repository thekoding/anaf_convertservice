//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.02.13 at 10:24:33 AM EET 
//

package com.kodingtech.models;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * Java class for OperatieType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class.
 * 
 * <pre>
 * &lt;complexType name="OperatieType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="tip" use="required" type="{mfp:anaf:dgti:d390:declaratie:v2}Str_listaTipuriSType" />
 *       &lt;attribute name="tara" use="required" type="{mfp:anaf:dgti:d390:declaratie:v2}Str_listaTariSType" />
 *       &lt;attribute name="codO" type="{mfp:anaf:dgti:d390:declaratie:v2}Str12" />
 *       &lt;attribute name="denO" use="required" type="{mfp:anaf:dgti:d390:declaratie:v2}Str200" />
 *       &lt;attribute name="baza" use="required" type="{mfp:anaf:dgti:d390:declaratie:v2}IntNeg18SType" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "OperatieType")
public class OperatieType {

    @XmlAttribute(name = "tip", required = true)
    protected StrListaTipuriSType tip;
    @XmlAttribute(name = "tara", required = true)
    protected StrListaTariSType tara;
    @XmlAttribute(name = "codO")
    protected String codO;
    @XmlAttribute(name = "denO", required = true)
    protected String denO;
    @XmlAttribute(name = "baza", required = true)
    protected long baza;

    /**
     * Gets the value of the tip property.
     * 
     * @return possible object is {@link StrListaTipuriSType }
     * 
     */
    public StrListaTipuriSType getTip() {
        return tip;
    }

    /**
     * Sets the value of the tip property.
     * 
     * @param value allowed object is {@link StrListaTipuriSType }
     * 
     */
    public void setTip(StrListaTipuriSType value) {
        this.tip = value;
    }

    /**
     * Gets the value of the tara property.
     * 
     * @return possible object is {@link StrListaTariSType }
     * 
     */
    public StrListaTariSType getTara() {
        return tara;
    }

    /**
     * Sets the value of the tara property.
     * 
     * @param value allowed object is {@link StrListaTariSType }
     * 
     */
    public void setTara(StrListaTariSType value) {
        this.tara = value;
    }

    /**
     * Gets the value of the codO property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getCodO() {
        return codO;
    }

    /**
     * Sets the value of the codO property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setCodO(String value) {
        this.codO = value;
    }

    /**
     * Gets the value of the denO property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getDenO() {
        return denO;
    }

    /**
     * Sets the value of the denO property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setDenO(String value) {
        this.denO = value;
    }

    /**
     * Gets the value of the baza property.
     * 
     */
    public long getBaza() {
        return baza;
    }

    /**
     * Sets the value of the baza property.
     * 
     */
    public void setBaza(long value) {
        this.baza = value;
    }

}
