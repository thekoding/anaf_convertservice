//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.02.13 at 10:24:33 AM EET 
//

package com.kodingtech.models.D390;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * Java class for Str_listaTariSType.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="Str_listaTariSType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;maxLength value="2"/>
 *     &lt;enumeration value="AT"/>
 *     &lt;enumeration value="BE"/>
 *     &lt;enumeration value="BG"/>
 *     &lt;enumeration value="CZ"/>
 *     &lt;enumeration value="CY"/>
 *     &lt;enumeration value="DK"/>
 *     &lt;enumeration value="EE"/>
 *     &lt;enumeration value="DE"/>
 *     &lt;enumeration value="EL"/>
 *     &lt;enumeration value="FI"/>
 *     &lt;enumeration value="FR"/>
 *     &lt;enumeration value="IE"/>
 *     &lt;enumeration value="IT"/>
 *     &lt;enumeration value="LV"/>
 *     &lt;enumeration value="LU"/>
 *     &lt;enumeration value="LT"/>
 *     &lt;enumeration value="MT"/>
 *     &lt;enumeration value="GB"/>
 *     &lt;enumeration value="NL"/>
 *     &lt;enumeration value="PL"/>
 *     &lt;enumeration value="PT"/>
 *     &lt;enumeration value="SI"/>
 *     &lt;enumeration value="SK"/>
 *     &lt;enumeration value="ES"/>
 *     &lt;enumeration value="SE"/>
 *     &lt;enumeration value="HU"/>
 *     &lt;enumeration value="HR"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "Str_listaTariSType")
@XmlEnum
public enum StrListaTariSType {

    AT, BE, BG, CZ, CY, DK, EE, DE, EL, FI, FR, IE, IT, LV, LU, LT, MT, GB, NL, PL, PT, SI, SK, ES, SE, HU, HR;

    public String value() {
        return name();
    }

    public static StrListaTariSType fromValue(String v) {
        return valueOf(v);
    }

}
