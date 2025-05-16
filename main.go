//  Copyright 2014 Cory Benfield
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package main

import (
	"encoding/pem"
	"io"
	"os"

	"mkcertfile/certs"
)

func WriteCerts(out io.Writer, certs certs.CertList) {
	for _, cert := range certs {
		io.WriteString(out, "\n")

		io.WriteString(out, "# Issuer: "+cert.Issuer+"\n")
		io.WriteString(out, "# Subject: "+cert.Subject+"\n")
		io.WriteString(out, "# Label: "+cert.Label+"\n")
		io.WriteString(out, "# Serial: "+cert.Serial+"\n")
		io.WriteString(out, "# MD5 Fingerprint: "+cert.MD5Fingerprint+"\n")
		io.WriteString(out, "# SHA1 Fingerprint: "+cert.SHA1Fingerprint+"\n")
		io.WriteString(out, "# SHA256 Fingerprint: "+cert.SHA256Fingerprint+"\n")
		pem.Encode(out, cert.PEMBlock)
	}
}

func main() {
	dat, _ := os.ReadFile(os.Args[1])
	label := os.Args[2]
	out := os.Stdout
	certificates, _ := certs.DecodePEMBlock(dat, label)
	WriteCerts(out, certificates)

}
