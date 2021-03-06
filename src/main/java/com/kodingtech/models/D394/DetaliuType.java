//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.02.13 at 04:09:50 PM EET 
//

package com.kodingtech.models.D394;

import java.math.BigInteger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * Java class for DetaliuType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class.
 * 
 * <pre>
 * &lt;complexType name="DetaliuType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="bun" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Int_nomenclatorBunuriSType" />
 *       &lt;attribute name="nrLivV" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="bazaLivV" type="{mfp:anaf:dgti:d394:declaratie:v3}IntNeg15SType" />
 *       &lt;attribute name="nrAchizC" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="bazaAchizC" type="{mfp:anaf:dgti:d394:declaratie:v3}IntNeg15SType" />
 *       &lt;attribute name="tvaAchizC" type="{mfp:anaf:dgti:d394:declaratie:v3}IntNeg15SType" />
 *       &lt;attribute name="nrN" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="valN" type="{mfp:anaf:dgti:d394:declaratie:v3}IntNeg15SType" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DetaliuType")
public class DetaliuType {

    @XmlAttribute(name = "bun", required = true)
    protected BigInteger bun;
    @XmlAttribute(name = "nrLivV")
    protected Long nrLivV;
    @XmlAttribute(name = "bazaLivV")
    protected Long bazaLivV;
    @XmlAttribute(name = "nrAchizC")
    protected Long nrAchizC;
    @XmlAttribute(name = "bazaAchizC")
    protected Long bazaAchizC;
    @XmlAttribute(name = "tvaAchizC")
    protected Long tvaAchizC;
    @XmlAttribute(name = "nrN")
    protected Long nrN;
    @XmlAttribute(name = "valN")
    protected Long valN;

    /**
     * Gets the value of the bun property.
     * 
     * @return possible object is {@link BigInteger }
     * 
     */
    public BigInteger getBun() {
        return bun;
    }

    /**
     * Sets the value of the bun property.
     * 
     * @param value allowed object is {@link BigInteger }
     * 
     */
    public void setBun(BigInteger value) {
        this.bun = value;
    }

    /**
     * Gets the value of the nrLivV property.
     * 
     * @return possible object is {@link Long }
     * 
     */
    public Long getNrLivV() {
        return nrLivV;
    }

    /**
     * Sets the value of the nrLivV property.
     * 
     * @param value allowed object is {@link Long }
     * 
     */
    public void setNrLivV(Long value) {
        this.nrLivV = value;
    }

    /**
     * Gets the value of the bazaLivV property.
     * 
     * @return possible object is {@link Long }
     * 
     */
    public Long getBazaLivV() {
        return bazaLivV;
    }

    /**
     * Sets the value of the bazaLivV property.
     * 
     * @param value allowed object is {@link Long }
     * 
     */
    public void setBazaLivV(Long value) {
        this.bazaLivV = value;
    }

    /**
     * Gets the value of the nrAchizC property.
     * 
     * @return possible object is {@link Long }
     * 
     */
    public Long getNrAchizC() {
        return nrAchizC;
    }

    /**
     * Sets the value of the nrAchizC property.
     * 
     * @param value allowed object is {@link Long }
     * 
     */
    public void setNrAchizC(Long value) {
        this.nrAchizC = value;
    }

    /**
     * Gets the value of the bazaAchizC property.
     * 
     * @return possible object is {@link Long }
     * 
     */
    public Long getBazaAchizC() {
        return bazaAchizC;
    }

    /**
     * Sets the value of the bazaAchizC property.
     * 
     * @param value allowed object is {@link Long }
     * 
     */
    public void setBazaAchizC(Long value) {
        this.bazaAchizC = value;
    }

    /**
     * Gets the value of the tvaAchizC property.
     * 
     * @return possible object is {@link Long }
     * 
     */
    public Long getTvaAchizC() {
        return tvaAchizC;
    }

    /**
     * Sets the value of the tvaAchizC property.
     * 
     * @param value allowed object is {@link Long }
     * 
     */
    public void setTvaAchizC(Long value) {
        this.tvaAchizC = value;
    }

    /**
     * Gets the value of the nrN property.
     * 
     * @return possible object is {@link Long }
     * 
     */
    public Long getNrN() {
        return nrN;
    }

    /**
     * Sets the value of the nrN property.
     * 
     * @param value allowed object is {@link Long }
     * 
     */
    public void setNrN(Long value) {
        this.nrN = value;
    }

    /**
     * Gets the value of the valN property.
     * 
     * @return possible object is {@link Long }
     * 
     */
    public Long getValN() {
        return valN;
    }

    /**
     * Sets the value of the valN property.
     * 
     * @param value allowed object is {@link Long }
     * 
     */
    public void setValN(Long value) {
        this.valN = value;
    }

}
