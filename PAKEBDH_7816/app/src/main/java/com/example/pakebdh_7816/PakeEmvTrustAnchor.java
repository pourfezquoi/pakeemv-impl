package com.example.pakebdh_7816;

import org.bouncycastle.util.encoders.Base64;

/** Public laboratory CA pin installed independently of protocol messages.
 * Regenerate deliberately using PAKEBDH_7816/tools/provision_test_trust.py.
 * This trusts the existing self-signed issuer as the suite's CA anchor.
 */
final class PakeEmvTrustAnchor {
    private PakeEmvTrustAnchor() { }
    static final String CERTIFICATE_SHA256 = "f7c088eef0677c4a1aca977c612d2061f47a51c7eb53d05258c4ea63b9ad63d8";
    static final String PUBLIC_KEY_SHA256 = "8a77a641545887b4b820413e3dd02b0e87d984e82b8c5d97c71ef807d40a4b61";
    private static final String PUBLIC_KEY =
            "ow/jtfLgTLJtoozxpSeaNkAAFErZtbl/HB2c2RgX4lNkT3JmbJ7te6MFDQYeN7QtvCAzfsrfDxIPs7KPaHqdtYPbZ7iS2NsJ" +
            "NiUAePHXCa7QByZCoBhhm6nkXV9/EgKC/6d86lFwHvImw/wXoJjh43E/cOK8FuIvLbtSwNVZAByALK8fqyZmwAK9oPM8FziZ" +
            "dkIMKW2mpeu1aUEre8+cmIWoUl3ppdID0eCPYVVmAe8um7OARMxghK8BNLuaqLMhO9IlohTWuo3lkuP93Al/ixVeAtD52xKK" +
            "K+5YJWlB08CdrbI2r0UrdImR7ZT/UVUF/OJB52DDzXfl9al07o5qCjsS2BZrRUIuXDNPG8xF2w2eb+8wj4dxysflcQ+jsJwh" +
            "rW8B64V9JGgT7t0+vlwEzOhx04Ldu92zKaxDqgwafwMX2XOWBGpye+iRNkuxlCm94lVgdEmGTHP6y+rEltsxpQYMVWuvYBBs" +
            "+o91ymPGO17Mhw1ah08QlNAwvGPhbmFSg4qkWcHhGScajokVt0jt1RI8CBgP+ea4yu2/doLBDajWd1LIwTLKdz1LZFzo0ZUS" +
            "lgSo2F0DmdK80EtF9Bkf+HNdFwOFfM1T0ECthqPbupeSsSEmogw/v16UKnMfq2K8Dby8SQabA6v1m/inzeuw7iwzL77k+7d8" +
            "6PWshReLOMqvvbttD72HzSm3FTNoW5XsI5+ntC7+1N7BQauxwIZq+XvbmSn1+s96AG2Qr/pr/2rUrYR1BJ5XcSmPUVq99CR6" +
            "GG/IXT59dFNi/i6JwIW1wrHeRCaOGX6LZReKt7y3QKBT+lrGUbAv35SrTJCtLCYuCdrIeKoMnWFcEUcWA/CLdz11bvXIWZJt" +
            "YbmpTjY6g01DFX72L3ondVBIcEi3SJGJuGXMFjgsusMWbCSbii+4sckH867NvCd6/i6UE17IegXWJ7Q+v4tYvX3VqZE8YzYD" +
            "usP0xKGf3QD2Vkf01zJNBAvLxf0QEe6JNXBdAr0vvcPBYdwhe+/AgQ7+XW2oNU105kDjC+UdXf02jezOcCsev/eOKI8OIIn+" +
            "5e8BTo5Kxj/RKiZuVOGIbcq0i0+15cSq6K6PYRtNmaF/j+Ob6Q32uc6N26h6rovZu5Iwdo5/h+4oBdGsq0LEZXFOtpc/KFaS" +
            "gaI2ZBaXTlFTAx5nWTc17GgQl31esEhPLj+8B6nQzd1Cu1lgW25Mf2O2IhB5Lj/yV0/MAuJgspVF2BWeBhhPOS0rtE+p3qlm" +
            "cIc6mNCr4WZN6IpfAUaqsmTZ2cW8SWiR1VXR0KaRzWPtBYU07H56ilS4kLLgjjuN6a+cIPelwkfZ5gwysqDEIghvzIyqfZ/r" +
            "wJ+nUemnUMX2ldNYZTmJ9QOu149WRJK/n5yPtNxYKF+LrPzcfXCehEk0ORNI/Md9Bs8Mu+bk9lckoNudKgVTXYu+NzVrD8dy" +
            "6aiAcby3U/4esSMAZSmn/7wCQnz8A2NF3mom/V//10tabHvrwAXYrXYTbUI6yO5IrAAcJB23zc3iyAOtkAGYxh5jqxv+J5BI" +
            "V0tA2Kq1ZMv3D/vYMZlE4fT1Nfk08xjSDcgKS4kFtewvKWJIZ+iZ9a09DGhr02pRW7slsOH1Bw/0OG+3HRxAeINyImApiv/G" +
            "KxtU6u5jizwleQyF2i2QCcI+7YXYeN9NKVPOlOz6E1MouYdbmnjY7Q/kKY739C89rTqwiP+9cD+acPE4VsLPypdxH+1evTOV" +
            "QyssS/EKObwZx+iCEWyKOQ==";

    static byte[] publicKey() { return Base64.decode(PUBLIC_KEY); }
}
