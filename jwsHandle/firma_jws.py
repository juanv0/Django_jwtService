import sys
#i did use chilkat becouse it was lon time ago when i write this code
#i did split the code in function to be reusable in this django api
import chilkat

#  This requires the Chilkat API to have been previously unlocked.
#  See Global Unlock Sample for sample code.

#  Note: This example requires Chilkat v9.5.0.66 or greater.

#just for load our private key, to strip the public, and for verifyin the signature
def load_key():
    #  First Upload the key
    sbPf12 = chilkat.CkPfx()
    success = sbPf12.LoadPfxFile("jwsHandle\hst_keystore_v4.ssl.p12", "Tuya2018")
    if (success != True):
        print("Failed to load p12 file.")
        sys.exit()
    #  Load the PEM into a private key object.
    private_key2 = sbPf12.GetPrivateKey(0)

    if not success:
        print(private_key2.lastErrorText())
        sys.exit()
    return private_key2


#this function will make this json a jws one, with a public certificate
def sign_json(body):

    private_key = load_key()
    rsa_key2 = private_key.getJwk()
    json = chilkat.CkJsonObject()
    json.Load(rsa_key2)
    json.put_EmitCompact(False)
    print("RSA Private Key in JWK format:")
    print(json.emit())

    #  Note: This example loads the RSA key from JWK format.  Any format can be loaded
    #  into the private key object. (See the online reference documentation..)
    rsaKey2 = chilkat.CkPrivateKey()
    success = rsaKey2.LoadJwk(json.emit())
    if not success:
        print(rsaKey2.lastErrorText())
        sys.exit()

    #  Create the JWS Protected Header
    jwsProtHdr = chilkat.CkJsonObject()
    jwsProtHdr.AppendString("alg","RS256")

    jws = chilkat.CkJws()

    #  Set the protected header:
    signatureIndex = 0
    jws.SetProtectedHeader(signatureIndex,jwsProtHdr)

    #  Set the RSA key:
    jws.SetPrivateKey(signatureIndex,rsaKey2)

    #  Set the payload.
    bincludebom = False
    payload_to_sign = body.decode("utf-8")
    print(payload_to_sign)
    jws.SetPayload(payload_to_sign, "utf-8", bincludebom)

    jws.put_PreferCompact(False)
    jws.put_PreferFlattened(True)
    #  Create the JWS
    #  By default, the compact serialization is used.

    jwsCompact = jws.createJws()
    print(jwsCompact)
    if (jws.get_LastMethodSuccess() != True):
        print(jws.lastErrorText())
        sys.exit()
    json = chilkat.CkJsonObject()
    json.Load(jwsCompact)
    json.put_EmitCompact(False)
    print (json.emit())
    return json.emit()

#this method will verify the signature, mostly done by decoding the jws json, and comparing the protected header
def unsign_json(body):

    rsa_key2 = load_key()
    print(rsa_key2)
    jws2 = chilkat.CkJws()

    #  Load the JWS.
    success = jws2.LoadJws(body.decode("utf-8"))

    # rsaPubKey is a CkPublicKey
    rsaPubKey = rsa_key2.GetPublicKey()

    #  Set the RSA public key used for validation.
    signatureIndex = 0
    jws2.SetPublicKey(signatureIndex, rsaPubKey)

    #  Validate the 1st (and only) signature at index 0..
    v = jws2.Validate(signatureIndex)
    if (v < 0):
        #  Perhaps Chilkat was not unlocked or the trial expired..
        print("Method call failed for some other reason.")
        print(jws2.lastErrorText())
        sys.exit()

    if (v == 0):
        print("Invalid signature.  The RSA key was incorrect, the JWS was invalid, or both.")
        sys.exit()

    #  If we get here, the signature was validated..
    print("Signature validated.")

    #  Recover the original content:
    print(jws2.getPayload("utf-8"))

    #  Examine the protected header:
    # joseHeader is a CkJsonObject
    joseHeader = jws2.GetProtectedHeader(signatureIndex)
    if (jws2.get_LastMethodSuccess() != True):
        print("No protected header found at the given index.")
        sys.exit()

    joseHeader.put_EmitCompact(False)

    print("Protected (JOSE) header:")
    print(joseHeader.emit())

    #  Output:

    #  	Signature validated.
    #  	In our village, folks say God crumbles up the old moon into stars.
    #  	Protected (JOSE) header:
    #  	{
    #  	  "alg": "PS256"
    #  	}
    return jws2.getPayload("utf-8")