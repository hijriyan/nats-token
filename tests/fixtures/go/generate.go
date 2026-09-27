package main

import (
	"encoding/json"
	"log"
	"os"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func kp(p nkeys.PrefixByte, b byte) nkeys.KeyPair {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	k, err := nkeys.FromRawSeed(p, raw)
	if err != nil {
		panic(err)
	}
	return k
}
func encode(claim jwt.Claims, signer nkeys.KeyPair) string {
	token, err := claim.Encode(signer)
	if err != nil {
		log.Fatal(err)
	}
	return token
}

func public(k nkeys.KeyPair) string {
	value, err := k.PublicKey()
	if err != nil {
		log.Fatal(err)
	}
	return value
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "verify" {
		var tokens map[string]string
		if err := json.NewDecoder(os.Stdin).Decode(&tokens); err != nil {
			log.Fatal(err)
		}
		for kind, token := range tokens {
			var err error
			switch kind {
			case "scoped_user":
				var claim *jwt.UserClaims
				claim, err = jwt.DecodeUserClaims(token)
				if err == nil {
					scope := jwt.NewUserScope()
					scope.Key = claim.Issuer
					err = scope.ValidateScopedSigner(claim)
				}
			case "generic":
				_, err = jwt.DecodeGeneric(token)
			default:
				_, err = jwt.Decode(token)
			}
			if err != nil {
				log.Fatalf("%s: %v", kind, err)
			}
		}
		return
	}
	op, ac, us, sv := kp(nkeys.PrefixByteOperator, 1), kp(nkeys.PrefixByteAccount, 2), kp(nkeys.PrefixByteUser, 3), kp(nkeys.PrefixByteServer, 4)
	out := map[string]string{}
	c := jwt.NewOperatorClaims(public(op))
	c.Name = "fixture-operator"
	out["operator"] = encode(c, op)
	a := jwt.NewAccountClaims(public(ac))
	a.Name = "fixture-account"
	out["account"] = encode(a, op)
	u := jwt.NewUserClaims(public(us))
	u.Name = "fixture-user"
	u.IssuerAccount = public(ac)
	out["user"] = encode(u, ac)
	x := jwt.NewActivationClaims(public(ac))
	x.ImportSubject = "foo.*"
	x.ImportType = jwt.Stream
	x.IssuerAccount = public(ac)
	out["activation"] = encode(x, ac)
	r := jwt.NewAuthorizationRequestClaims(public(us))
	r.UserNkey = public(us)
	r.Server.Name = "fixture-server"
	r.RequestNonce = "nonce"
	out["auth_request"] = encode(r, sv)
	q := jwt.NewAuthorizationResponseClaims(public(us))
	q.Audience = public(sv)
	q.Jwt = "fixture-jwt"
	q.IssuerAccount = public(ac)
	out["auth_response"] = encode(q, ac)
	g := jwt.NewGenericClaims(public(us))
	g.Data["type"] = "fixture-generic"
	g.Data["answer"] = float64(42)
	out["generic"] = encode(g, us)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Fatal(err)
	}
}
