package identity

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	k8s "k8s.io/api/core/v1"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_labels "k8s.io/apimachinery/pkg/labels"
	k8s_types "k8s.io/apimachinery/pkg/types"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"

	gomock "github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

var (
	testMTLSK8sSecret1, testMTLSK8sSecret2, testMTLSK8sSecret3 *k8s.Secret
	testMTLSK8sClient                                          k8s_client.WithWatch
	testCerts                                                  = map[string]map[string][]byte{}
)

func init() {
	certs := make(map[string]map[string]string)

	for _, k := range []string{"pets", "cars", "books", "john", "aisha", "niko"} {
		certs[k] = make(map[string]string)
	}

	certs["pets"]["tls.crt"], _ = url.QueryUnescape(`-----BEGIN%20CERTIFICATE-----%0AMIICmjCCAYICCQCmRAsdcSJkgzANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARw%0AZXRzMB4XDTIyMDYxMTExMzQzM1oXDTIzMDYxMTExMzQzM1owDzENMAsGA1UEAwwE%0AcGV0czCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKNBgs%2F1bs9ybvnJ%0AgiXP21n46jvUCUL6ST0gX%2FlcIGAzvBiSg4tPScbMyeQwsPnht5o1de8m06IZ9PKS%0ALpGO5vlM2wr8Fh97ILr8dwYLrV9OegWqtYNfMO%2BXoSqWjSisEdEB%2BwNSI3TIbp7E%0AAkMSZmgrUrKKuVuZM0OIGsQtTG8CZvSPI37OzM%2FmGNTI%2BcYhJzRVhLa61nn4vqVz%0AfgG2tRW5FYW%2Br7qhHcx8hVDv5npwltpoFN0MosrkNMegmIgvcyVmXdibMji2f%2FOh%0A%2FFrAfRr5%2BWs9xVkd2fzuZWq1OLBDXIzhYC0TpX3sytDQhGQi%2F95ZPqPCglBNVh2s%0A3zurxJcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEATXxgldjTMOvYz4txYfrHJ76y%0A%2FtSLddLxIJAeFdHmj1i4a%2FDh2%2BRpIwL%2B%2B40WJvpcuYCxqc2cUOelag6WCdd9%2BQdX%0A1nAynbY5KlX9A3PCWJY8OMGWXZ5eKhcQi%2FFGfECI9iCx5edaxjNw9dpPNTPa3Sgt%0A3NMfnR7Wx3bcER35TntGaTdXu6tguPbrbEyNUFbS5JIj%2BNzqWEwi5XaDvuFTZTjt%0AenaZzNi0qxvjFQGlh6AuQ3jIRx0hCQAaaxNwcW7uQfWE3vBEUyC06YH81r1vBzsU%0A%2Ba3fQAptefIL4MmbDL6WWrB0%2FLRF3Lw2lfQ4ptQJqwzG8gk%2BRsno6F1Om6IZVQ%3D%3D%0A-----END%20CERTIFICATE-----%0A`)
	certs["pets"]["tls.key"], _ = url.QueryUnescape(`-----BEGIN%20PRIVATE%20KEY-----%0AMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCjQYLP9W7Pcm75%0AyYIlz9tZ%2BOo71AlC%2Bkk9IF%2F5XCBgM7wYkoOLT0nGzMnkMLD54beaNXXvJtOiGfTy%0Aki6Rjub5TNsK%2FBYfeyC6%2FHcGC61fTnoFqrWDXzDvl6Eqlo0orBHRAfsDUiN0yG6e%0AxAJDEmZoK1KyirlbmTNDiBrELUxvAmb0jyN%2BzszP5hjUyPnGISc0VYS2utZ5%2BL6l%0Ac34BtrUVuRWFvq%2B6oR3MfIVQ7%2BZ6cJbaaBTdDKLK5DTHoJiIL3MlZl3YmzI4tn%2Fz%0AofxawH0a%2BflrPcVZHdn87mVqtTiwQ1yM4WAtE6V97MrQ0IRkIv%2FeWT6jwoJQTVYd%0ArN87q8SXAgMBAAECggEAHvqLbBLSmCLK1DNcsvgiU4xcRkYSC9ealjLSg2rr6dVn%0AV%2FJVa9X71fF%2BTgK%2FUmt2f5itbFgdyKDMTktW8t%2F%2FDEd9OTRkrkybBWBq5YbJu1AU%0A74ZZMziY%2FJ31QzOWTaV5LAQIMbUgbUSrWQ0wsLGJJTMzWhXg3nTPuXzWN2uxGU85%0AtjnpKUEgvfORpJcaTmfpsvmBk5oVRGMVVEHcN32jnVTE938IiCVNBJsekYhj3aEl%0Aeawtq8SSXjWLE5U2tVFHK4p4mqLC1Io80uYRaMu2r13DvO%2FETJbTlJTAQdPGw3mu%0ArLsi%2FteftZ6KmVT9iFN7HAke0Dpaw%2BYizY76BBUv4QKBgQDWPs5tlEveBnOvd7ro%0AhF3BTef7K04weWKo6YwoD7T46CVSKgVLmqO9VeQwjmjYt0AqQliOKguADj1ZeUTl%0AEyTbVEty3bXN0D3GXeLZc81%2FsN1OQLpet6lyyqsC9d7PXWffHhBQp0Q9%2BBa%2FkFx9%0Aoq7lpjmmfZJf1BZvFpVDsfPiEwKBgQDDErllEuTgzsrv6Ag%2Bbm3XzSpVz7FNrmbz%0APxcqmxkjdKFNW3om9kmE0al5oq7Lw%2BjOMW3SIA%2BVdr7fura5QFfRxLhaHlDmcJn2%0AfoySf5Zdxenh3hxIpqkEEbtBtrXKv8k%2Fi28pgHyEJu6o2y54m2QOs4x5PkpB%2BcRP%0AR0gyp3XD7QKBgCkqCB%2Blzq3qL3AXYSIrzJfHkDsCJxPJPtuVhAhufCcW85TF3h6Y%0Ap71JM37g3eRF0V5NQRaPnYYNNlxqoIIjG4HIwHZhgvz4deYXQ%2B7kASf3o43VgfmQ%0A8E3OAu2esCDHoZ2M%2BTWF7ea6NCS6aAr7pv8Y4RrMJcOjzGuruyI2ntVhAoGAJT1K%0A1SfBN8ViamASStDL%2BVl6Tn1irKCxmJgftQt8xg76yAjBjfSQXmGkB8ttsQqKQ%2Bqd%0Au3JRZ0gO8ijzvvOwkCQMyW9mJEe0rKDF9yWSL%2F6bQnojTh86vsMfy1C07aqlIZNd%0Auj%2BEBbpk7ylAete3RzMxiufAR04GEthZyQm86pUCgYA7PWLjzI7m4ubXdKpXs8ZW%0AXEtII7CEGvv0Z1r1zvzavnKfp7Um6%2BR1mJ5ro%2FESa%2FUWktxh0OuxS5nVf618Pk%2FM%0AvvBFsshCRuyfA0%2BCB6C%2Fvl%2FQaOV4hLYY6lEoBvimDSO1mf2XtCJWQLskXEnlDp1S%0AIc%2FM9q3gLh0qUBXXP5zSCg%3D%3D%0A-----END%20PRIVATE%20KEY-----%0A`)
	certs["cars"]["tls.crt"], _ = url.QueryUnescape(`-----BEGIN%20CERTIFICATE-----%0AMIICmjCCAYICCQC0%2Bxgjh%2FTpvjANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARw%0AZXRzMB4XDTIyMDYxMTExMzQ0MVoXDTIzMDYxMTExMzQ0MVowDzENMAsGA1UEAwwE%0AcGV0czCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKWxnlcRi2wfVR42%0A71%2BJdOQE75meYGtvaEK2ek6HXNWz3RsoBmsrbHbtRv6Z3eYuW59god5h7ywGcx0o%0AlEmdVQHIX8sqyJewSLcha9UofSdjOmNFzCqd5M4FBves0cI1%2ByfGvXd11PaRo%2FOV%0AtAsimT6vqgDn6pmjKwefnnsblnho93dDtHQA9aBJGJ45R%2FaScqmyyVxuxjXAeDTZ%0AVhmLeMw4UytjmgnVkpkK2Ef%2Bl3fosqKPqahK28Lx%2BwRY5odPM0S2nOYse0HMwkVX%0A0kCJkOKv4HWZQmUhtERpdgaunWi6HuibCflKYyx4JQbMExEYZCyOqfQKwV3yrVNL%0AS3e8es0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAgXWzWoQ8RypgXC0iNI%2FsTnqr%0Aihpvt%2Bh9ocbgQoqeWL%2BU6uOiBmreoja3qnIaGVav4C5fihp7wGQ2CHR0XRqJQDfZ%0AB4fHMCsq3hVtWGZpDAVaZOQSj%2F2YySKHDSQ3DudmmIgp8CAlX%2ByzyDTpGBA4tD%2BC%0AtA8Q%2Bp%2BE%2Fde1SA1jIAJ5BqqAn7y%2FnDAeIYvEvQsJX7ipwzqIGuuPKG%2Fd7Gi%2FO2UT%0AqjHc9l%2Fhm4y52hHbWbXGEOBPXe1TRKiFvmUIQav6C537rizLVRBtX2OeznWqMF9B%0AYd9W%2FPdWD9lWqVaL26wakaJ2Cvcu6GsZl3C%2FYzKFk5btmFe8MjIXpWrhrKS32g%3D%3D%0A-----END%20CERTIFICATE-----%0A`)
	certs["cars"]["tls.key"], _ = url.QueryUnescape(`-----BEGIN%20PRIVATE%20KEY-----%0AMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQClsZ5XEYtsH1Ue%0ANu9fiXTkBO%2BZnmBrb2hCtnpOh1zVs90bKAZrK2x27Ub%2Bmd3mLlufYKHeYe8sBnMd%0AKJRJnVUByF%2FLKsiXsEi3IWvVKH0nYzpjRcwqneTOBQb3rNHCNfsnxr13ddT2kaPz%0AlbQLIpk%2Br6oA5%2BqZoysHn557G5Z4aPd3Q7R0APWgSRieOUf2knKpsslcbsY1wHg0%0A2VYZi3jMOFMrY5oJ1ZKZCthH%2Fpd36LKij6moStvC8fsEWOaHTzNEtpzmLHtBzMJF%0AV9JAiZDir%2BB1mUJlIbREaXYGrp1ouh7omwn5SmMseCUGzBMRGGQsjqn0CsFd8q1T%0AS0t3vHrNAgMBAAECggEATX0AeOWal2kbzHKShdJp2Q055FS98OB8GN7v2fPSBZsF%0AJ2MThWEca43R6tWYgcJiVOnDKZYRXTxy70r%2F9mFe1OOZcRFEGDR3%2FTTjEh%2FKT%2FZG%0A4xBMSA3paDPPq1qmCjZmi5aVGt3%2FR4Sa8RqsxZxboIZUcfIDs%2FAr%2Bne6jQY823gy%0AxtBV3YxQiuc9tzM8Nb3C%2BomBkY%2Fo1vkyfDgSidYIUd1VRk%2FhNIL3dr5Le3edmFxW%0APH%2FqmkayIT7tMGapXBoz6Tt%2B1Z1k8rvbm%2F6GIfQZLtBZSNic5nrefs64zvnQ79NW%0AZ%2BHmdZZU%2F2uEszLZ9aamK%2Bhq8F3s33WBOuxQc0bbvQKBgQDPZympuEwZi4gB7m3a%0AZ8epY44GULDqK81xa4ladPRDFjea%2FbM%2BoJuusMYNG6AH0JYzsXKT58V9vcAWLxog%0AQLQLlfPMSqrbWcgONiYPq0Trz3bO0rp2nVkmuWONO1ftgERy9Q44iYhwNwkrK6ZM%0AJ53IIDVHSjsDFv17UM2ipDDfswKBgQDMhJQNNOKSqvySKPmhnrZmV8Wf3S4XL1O6%0AwdcsJcBHRwQPMNySVbAY1QBO%2BLllQ6Av5vbA%2FOQu2nqiJI4EmuvXZLppXAyobuxn%0AFSpXhfj4AlidsQ3OiTc5vmX563MFH%2BkYSIKzQSBndqC3B2l1BMDqSoVyZKT5y3xm%0A79OWmrP7fwKBgQCRUYgYmcAAWgqGx%2BeCkxqLbezSMfFzchN1d9J6Zd3Lr6JwX3ga%0A1m%2Bee8%2BY2ZVMRHMpbxiH12pByxTutjwJAyzjvUJgDqUeIg8RHhGXAvq8etWU3oO1%0AnlQb1OOSzlSyXSAYp%2Bk55euKLJWpAOF5FHzx%2Ftc1xyYH6TDcGWaroX15DwKBgQCq%0AgYWlFQgoWyFDAaJNGjLbVCXQx%2BebMLvPobeweLC7O%2FuoZoYeAg5URZCCRl7ai%2BzK%0AwvXJo4zhewhukadNM5OX%2BcRn%2FnQXIJM6xayNV4ZfziTvIyNto3xFSfVezOsRxK7i%0AreE5bPyFBaOrtCQ5iQME0ag73KimEP3gG%2BX9U3DmJQKBgG%2FS%2FA4GRohr1bBkXEeP%0A48GEoJWq4%2B6yVdwpBzPIXBlkNj6ZSEd9VWusIsa%2B2eqnv5tW9OQEdo3XsdWsAqPK%0A7b8M1NTuLzDnouaou%2BjfoBNB9vL8%2BnIQGGqfyl9jtfuYtjEKxWi41RbUZw2kt6cd%0AYAbHhGbdvx9saAqJMKKbE1O3%0A-----END%20PRIVATE%20KEY-----%0A`)
	certs["books"]["tls.crt"], _ = url.QueryUnescape(`-----BEGIN%20CERTIFICATE-----%0AMIICmjCCAYICCQCfjfMh66x63jANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARw%0AZXRzMB4XDTIyMDYxMTExMzQ1MFoXDTIzMDYxMTExMzQ1MFowDzENMAsGA1UEAwwE%0AcGV0czCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRMbdvVSLyDFXu%0ArDYPRHMsxUvfnLQYSxSGOxwNY0Cc1C6aZOWDfTtr4PMyfnYEfn9%2BZm2QhqCYY%2Bm3%0A0ExZbpyxlamQi1EEM6LVNjcdGeDFN24R4fWC%2BMNdvV1L4Uc20Z6vqjr%2Fmw9vEm6K%0Asvz5ChUGBytDXAAkun%2FWNH%2FfN3P7%2B2lWJgAoip%2B2MXKHzgkAim8vwoh8UugoF30J%0APWCHfn37cdEQ9JqAeRSaj6qFHn4QOstxDm5V2lq%2FZs1sozyoHwvun80ECod3fqdV%0A2g4J%2F1527aV%2B8x2TdE6gHp40BPiaWu3RgzvYfH2WUs6D63IrVtHW1k8t%2BWp0WeZL%0AiAgdrckCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA0fAegaugnNgwZ0lYiWO%2FUlsK%0A%2FEKW6j37Um4afVSO9s68jdUuvBTdLrbWSI3ipNyFRjca4h9yx7iyzAv256b8wMJ7%0AzuDNgMcwZQrssjFLtjE4Mz18r9DC0Up8CCEKqzRYx9o90l29o%2BsuikWbMIB3Szum%0AEy%2B6cN29PvjX4oHlYC750IepPQhQVW0DXGAPy1Jllc%2FtjeHNrYZjzOE1q1OqY4EM%0AO91uL6P7TgO9s1iFSIQmWqDSKl11qoRet3PHCoC1Gg6lOubUVWYIC8Cfy5yi87Qy%0A7rMFA3Wu7HNkIUleFqy1CblMNxb2wdqYsRkcID6j7W17NmgpblyzxHYk2Mn3OQ%3D%3D%0A-----END%20CERTIFICATE-----%0A`)
	certs["books"]["tls.key"], _ = url.QueryUnescape(`-----BEGIN%20PRIVATE%20KEY-----%0AMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSETG3b1Ui8gxV%0A7qw2D0RzLMVL35y0GEsUhjscDWNAnNQummTlg307a%2BDzMn52BH5%2FfmZtkIagmGPp%0At9BMWW6csZWpkItRBDOi1TY3HRngxTduEeH1gvjDXb1dS%2BFHNtGer6o6%2F5sPbxJu%0AirL8%2BQoVBgcrQ1wAJLp%2F1jR%2F3zdz%2B%2FtpViYAKIqftjFyh84JAIpvL8KIfFLoKBd9%0ACT1gh359%2B3HREPSagHkUmo%2BqhR5%2BEDrLcQ5uVdpav2bNbKM8qB8L7p%2FNBAqHd36n%0AVdoOCf9edu2lfvMdk3ROoB6eNAT4mlrt0YM72Hx9llLOg%2BtyK1bR1tZPLflqdFnm%0AS4gIHa3JAgMBAAECggEAZWC%2B6ZPlNnQx19bTbVN46UyV%2BsPz0EZZFZKiPCuJ1sjY%0A7ZS9VLZcXaz2ZufbeAE7OzQ5Im85SY%2FByC1ZbT9Lzns1ixui4HpyoQbcn0SAFKWY%0A1pnyvpVykHZQyRGxqrid%2BUM1mDt7DbvA3XA6aTOW1gaOtyZO5BLVnpQ1yfBjxqjY%0AQ3B5Y7ryh9QBZDJqXSlgqU9TpR2OBgXDK4kjeuv3ZkIB%2Fe6nnQ8%2FQxGQ%2FGM5DrQG%0ATOBnuYyTCTJMiDtpqttxs9yA6JqSs4PHWrAOrA0Unh7qVe7XRHvGMXB4BdmT1gUS%0AS07ItFu%2BIQIfAucQ0W9UUv0lo7QryncOzmNME6fIMQKBgQD87XSCBKzW34lNRlfY%0AFiU9urBVjGsgmfn0OzVNMwxB7gqenVBub2jf1OtIkXApZP6kqPMTNxMQtsAub4zh%0AXIjiWnBoo9hkmN04aQUsSVAYrvPTy%2BRttn35IaJrNSeKe%2FG8wOeIaNLCp6DE3zSx%0AqRDzwtYGxBYtGmhMg8DcvLGecwKBgQDUnnQSezSNjnUEGBVLVB4LgnnyRkvm3zIc%0AQNql5%2BBtJCX8KKRHhbkOmCmgqudDPSjbYWjuinc7jwnj8OVHP23Xpvw31O5uGShR%0AlmqBDkmMt9Ys0NHwku3lQ2gDVC92s8GDRIH0Utc2m7ZKdEMvGOjehfl0yRQ9pBr%2F%0A%2BCsS%2BOVX0wKBgF%2B0%2FtRALqL0XUE3cAAdiSQNo7ILe3IPscygJvA6c9Xy3GPexVO0%0ApqukJxADsLyJMe5e2%2FQWcAlwDdLEdTvFxypX7Jc8AKM4UOWKn%2BF9MGjWsv8e9SYq%0A2wpNlucYawj1E6lIGZS9jZsI0UYN7COaBQcoX9KZmoagqnzhkjY01MVPAoGAds0u%0A2CDFhY8i7S2zwEp5Gz9Fek0zHgZ6jnTidy8wJGu9Wb8vw9MBSxlUsTStUdG7oZE1%0AO4xdAQd0pEu3IO9dJdFlPqEYtKYT9DqSuhfMmvchkhsAI2dFzAO0%2B58vgikAqKM%2F%0A5c%2Ff9uBcpA%2BAdrF5dNTxRQMR7zth5sK49rniFAcCgYEAwUS7WPYz9yVeVb6PiOg1%0AXVBcYtbSToGrGufvxeQ40fY%2BpS0tVZEwK8Q%2FEN3%2Fp0NTZzitHi4S7CgXw3%2FV1sCi%0AEPKhde5S1fyszYtPmu7u4r7Qn%2FdJvMB2ZGffp0gbC9HZRh4veaPb8cUpdDtHu5%2FG%0A0NLpVsq%2FZKmPbqafwaE72xQ%3D%0A-----END%20PRIVATE%20KEY-----%0A`)

	certs["john"]["tls.crt"], _ = url.QueryUnescape(`-----BEGIN%20CERTIFICATE-----%0AMIICuDCCAaACCQCg8Pi%2BR7xlUTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARw%0AZXRzMB4XDTIyMDYxMTEyMzc0MFoXDTI2MDYxMDEyMzc0MFowLTENMAsGA1UEAwwE%0Aam9objELMAkGA1UEBhMCVUsxDzANBgNVBAcMBkxvbmRvbjCCASIwDQYJKoZIhvcN%0AAQEBBQADggEPADCCAQoCggEBALPIWAAY%2BGCnHxnCd3iJMP5jx8JEvImmII2anU9B%0AB3i%2FdGq4oPv%2BIbQZcWS6YQbJdm8pAwkR9IIhz0csMMPoJuX1ZD7QsNWEEI3hXypZ%0A1iwZNJinU2MvvLuQRnnD1qpwd4SSq%2BNH1IqyCYAHpYq2ROQsFyr1s4iA0y0JM0vH%0AMAxG7QSO8IHAGMG%2FgQWcIge8Ko%2Bu5T%2BJ1IEmlkUrGMj4PvRhD05A7PLXddGZnhrb%0AtWhfN15B5BRJMyD5PlUFiCG4avKXSKO%2FBOCY8aXPraUBiCVzpGtOGPDbVKieZe1i%0AXKbKQUa3KLW%2BlZLUdRSgvmYSVpLtne%2Fjya1V6u0bkpQxniECAwEAATANBgkqhkiG%0A9w0BAQsFAAOCAQEAkHrqNj6idfRrRXAIIAwTDFAJC9KcTVkh3%2F1x0H8FxKyp65we%0A151C8uJMecFfKBdXFQv05IKYWksvEVoEUOODPrM%2Bzl89eKWgoAEtaJ3TAp2cgcqp%0ANo0vKGz6fP03KuHvLDOvCXfqEf8IM%2FN2Lwxfl9r0I5naSgx7QzfsMO3G34bZy4mI%0Aai6Rmth0HklUTDQUOd5ZoxsaTBPFPqApMLYMQzpKKB9mdx5kLiHJsV%2FnVSnzqtgh%0AsHeYSKHwid1Hb6t7%2BjaEHXH3Rj45h1I5Ib0Ax%2Bfo25B0cbVrY8mbZIhWS2jSjBVF%0Ac0tfkcSZ1r3ML8tqkuRpmbiTSm1ObX92sRrV2g%3D%3D%0A-----END%20CERTIFICATE-----%0A`)
	certs["aisha"]["tls.crt"], _ = url.QueryUnescape(`-----BEGIN%20CERTIFICATE-----%0AMIICvDCCAaQCCQCJbRrcBLeKnTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARw%0AZXRzMB4XDTIyMDYxMTEyMzc0NVoXDTI2MDYxMDEyMzc0NVowMTEOMAwGA1UEAwwF%0AYWlzaGExCzAJBgNVBAYTAlBLMRIwEAYDVQQHDAlJc2xhbWFiYWQwggEiMA0GCSqG%0ASIb3DQEBAQUAA4IBDwAwggEKAoIBAQDzjA7PABY%2B20cj7ozywdeQL2JQKh%2Bk4B7p%0AfcT0sw3mb0mdyFVDF3xc7o4orWmfAzRwHSSimIeOYEDR%2FkeuKMWQfLMd3MaSLkGT%0Au8R5HYvN9NVxhhUpD%2FTIvCbUgXRQKMNhiDzyL9TL5ija%2BT8DN%2FMuIagzhz1jKAtG%0AWcew4rFWIl298kvKgE4Z8YFI4EDcBqn5FNELkz8%2Fl0T1lORvxc81MtqyR61HkD0s%0A5xYZrHNbmjyByG5UoFwVItQ1VHYQoiYW%2F0ifmYWcDx%2B4H0cux6PRR9Qrz%2FD2RneU%0Ai%2FsHNicFr5KzYaEtHEHiSGNbniD%2BEd%2FoE447IoaPamMVqSQR711zAgMBAAEwDQYJ%0AKoZIhvcNAQELBQADggEBAJ9Y6olsL76KQ%2FopJFFzChXmrIzGGma51bE%2F6jQzSRrD%0AHSZEZQT8O2g20qtgPDhWSe3mkIayCAwZ%2FxzQONNa8bjXsolqxeSyqtQv5MgGcDa%2B%0AumnUtCNcW1k%2F1e8bygV6ijJBM1tNpCzMqrz7F4y4ZnuZ7pkTzai6s7S8woFXLx%2FP%0AeC8uzDhDJTW5J%2F%2Bz%2BxAZl5ZpCwHskA8tgPqCo%2BwLrSevHwQhP%2FqZ8Wgd6DdNJ0w5%0ASieiephzQ3O0wTk6YjjxQGI%2BYprRY2T8bTamQ3A0dQGn0zqjFh2%2FlrIO61RMD8os%0AJdCBjuw4v5yXat5dsymjRffRSCioAslg0hMHWnqZjO0%3D%0A-----END%20CERTIFICATE-----%0A`)
	certs["niko"]["tls.crt"], _ = url.QueryUnescape(`-----BEGIN%20CERTIFICATE-----%0AMIICtzCCAZ8CCQCzPRO%2FsBHMzDANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARw%0AZXRzMB4XDTIyMDYxMTEyMzkwMFoXDTI2MDYxMDEyMzkwMFowLDENMAsGA1UEAwwE%0AbmlrbzELMAkGA1UEBhMCSlAxDjAMBgNVBAcMBU9zYWthMIIBIjANBgkqhkiG9w0B%0AAQEFAAOCAQ8AMIIBCgKCAQEAsAVZR9fk1%2BYs%2FXoXy9YDTKcgcrRsPyy72fsIMCxd%0Ahd35Gi3JMf8av35puuJ6zbdIBXbtlAwd8Kwb2YafOaTm0hJGqjyJ44%2FLw%2FzEER3S%0AW1OqNiNBjH2JX5Rgn7e6zP%2BO6W%2Bj9Ier5zkQt%2Fv3qJy5Tqgd%2FLP7BXlswdAYnPt0%0AXhZHsyOvyUAalItYPfU2SLbORz%2BTS1yv9UQj0Wbd3mSd8xK5d1fOYzHDY2qtDXIe%0AVdd6s7RH51OdxQe1nqxNLV7hkNqvMrmKqPOQzdXbylJa8KV%2BCsWikfFgi47%2FOMjl%0AFsXjvjdXK%2B%2By5PKYABH%2FqZgsDyotE0nu6F%2ByfOkxqe0w8QIDAQABMA0GCSqGSIb3%0ADQEBCwUAA4IBAQALFY0JLaX4aHsFc1KL0BxNyUEo8vIBk8oIUr0WwvmNEKnsSNMz%0AeHcj0YUmdiPgFQGbG%2FeDkPMGPBS2F2rrtDgyJ5fYRFRCh6bo6YLdSIljMCCW6MhU%0Ac%2Ffy3DIBaEEcbzPUK%2FP7s1FKiowFthLgRxjOtyD%2BkYlKdAbQ1QUxR43WXBcABFaW%0A3hL%2BrowcwJjJofrH0m78EzM%2BYXk5ldcEOT6%2FiF0eIynx59h0IFe2GyROQAqpoWht%0AiJ9YnZbuWQ1vT1kw1YSZx3ba90P8FSBULephM9rG24R20yUPNGP5Y6jfTh7odyie%0ALNrSFH8bvAz9snt%2B7TvDZBVCB3ZiiXewIBqB%0A-----END%20CERTIFICATE-----%0A`)

	for key, value := range certs {
		testCerts[key] = make(map[string][]byte)
		testCerts[key]["tls.crt"] = []byte(value["tls.crt"])
		if certKey, found := value["tls.key"]; found {
			testCerts[key]["tls.key"] = []byte(certKey)
		}
	}

	testMTLSK8sSecret1 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "pets", Namespace: "ns1", Labels: map[string]string{"app": "all"}}, Data: testCerts["pets"], Type: k8s.SecretTypeTLS}
	testMTLSK8sSecret2 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "cars", Namespace: "ns1", Labels: map[string]string{"app": "all"}}, Data: testCerts["cars"], Type: k8s.SecretTypeTLS}
	testMTLSK8sSecret3 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "books", Namespace: "ns2", Labels: map[string]string{"app": "all"}}, Data: testCerts["books"], Type: k8s.SecretTypeTLS}
	testMTLSK8sClient = mockK8sClient(testMTLSK8sSecret1, testMTLSK8sSecret2, testMTLSK8sSecret3)
}

func TestNewMTLSIdentity(t *testing.T) {
	var exists bool

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "", testMTLSK8sClient, context.TODO())

	assert.Equal(t, mtls.Name, "mtls")
	assert.Equal(t, mtls.LabelSelectors.String(), "app=all")
	assert.Equal(t, mtls.Namespace, "")
	assert.Equal(t, len(mtls.rootCerts), 3)
	_, exists = mtls.rootCerts["ns1/pets"]
	assert.Check(t, exists)
	_, exists = mtls.rootCerts["ns1/cars"]
	assert.Check(t, exists)
	_, exists = mtls.rootCerts["ns2/books"]
	assert.Check(t, exists)
}

func TestNewMTLSIdentitySingleNamespace(t *testing.T) {
	var exists bool

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", testMTLSK8sClient, context.TODO())

	assert.Equal(t, mtls.Name, "mtls")
	assert.Equal(t, mtls.LabelSelectors.String(), "app=all")
	assert.Equal(t, mtls.Namespace, "ns1")
	assert.Equal(t, len(mtls.rootCerts), 2)
	_, exists = mtls.rootCerts["ns1/pets"]
	assert.Check(t, exists)
	_, exists = mtls.rootCerts["ns1/cars"]
	assert.Check(t, exists)
	_, exists = mtls.rootCerts["ns2/books"]
	assert.Check(t, !exists)
}

func TestMTLSGetK8sSecretLabelSelectors(t *testing.T) {
	selector, _ := k8s_labels.Parse("app=test")
	mtls := NewMTLSIdentity("mtls", selector, "", testMTLSK8sClient, context.TODO())
	assert.Equal(t, mtls.GetK8sSecretLabelSelectors().String(), "app=test")
}

func TestMTLSAddK8sSecretBasedIdentity(t *testing.T) {
	var exists bool

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", testMTLSK8sClient, context.TODO())

	assert.Equal(t, len(mtls.rootCerts), 2)

	newSecretWithinScope := k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "foo", Namespace: "ns1", Labels: map[string]string{"app": "all"}}, Data: testCerts["cars"], Type: k8s.SecretTypeTLS}
	mtls.AddK8sSecretBasedIdentity(context.TODO(), newSecretWithinScope)
	assert.Equal(t, len(mtls.rootCerts), 3)
	_, exists = mtls.rootCerts["ns1/foo"]
	assert.Check(t, exists)

	newSecretOutOfScope := k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "bar", Namespace: "ns2", Labels: map[string]string{"app": "all"}}, Data: testCerts["cars"], Type: k8s.SecretTypeTLS}
	mtls.AddK8sSecretBasedIdentity(context.TODO(), newSecretOutOfScope)
	assert.Equal(t, len(mtls.rootCerts), 3)
	_, exists = mtls.rootCerts["ns1/bar"]
	assert.Check(t, !exists)

	newSecretInvalid := k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "inv", Namespace: "ns1", Labels: map[string]string{"app": "all"}}, Data: map[string][]byte{}, Type: k8s.SecretTypeTLS}
	mtls.AddK8sSecretBasedIdentity(context.TODO(), newSecretInvalid)
	assert.Equal(t, len(mtls.rootCerts), 3)
	_, exists = mtls.rootCerts["ns1/inv"]
	assert.Check(t, !exists)
}

func TestMTLSRevokeK8sSecretBasedIdentity(t *testing.T) {
	var exists bool

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", testMTLSK8sClient, context.TODO())

	assert.Equal(t, len(mtls.rootCerts), 2)

	// revoke existing trusted ca cert
	mtls.RevokeK8sSecretBasedIdentity(context.TODO(), k8s_types.NamespacedName{Namespace: "ns1", Name: "pets"})
	assert.Equal(t, len(mtls.rootCerts), 1)
	_, exists = mtls.rootCerts["ns1/pets"]
	assert.Check(t, !exists)

	mtls.AddK8sSecretBasedIdentity(context.TODO(), *testMTLSK8sSecret1)
	assert.Equal(t, len(mtls.rootCerts), 2)

	// revoke non-existing trusted ca cert
	mtls.RevokeK8sSecretBasedIdentity(context.TODO(), k8s_types.NamespacedName{Namespace: "ns1", Name: "foo"})
	assert.Equal(t, len(mtls.rootCerts), 2)

	// revoke trusted ca cert ot of scope
	mtls.RevokeK8sSecretBasedIdentity(context.TODO(), k8s_types.NamespacedName{Namespace: "ns2", Name: "books"})
	assert.Equal(t, len(mtls.rootCerts), 2)
}

func TestCall(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// john (ca cert: pets)
	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: url.QueryEscape(string(testCerts["john"]["tls.crt"])),
			},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,3],"Value":"john"},{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"}],"ExtraNames":null}`)

	// aisha (ca cert: cars)
	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: url.QueryEscape(string(testCerts["aisha"]["tls.crt"])),
			},
		},
	})
	obj, err = mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["PK"],"Organization":null,"OrganizationalUnit":null,"Locality":["Islamabad"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"aisha","Names":[{"Type":[2,5,4,3],"Value":"aisha"},{"Type":[2,5,4,6],"Value":"PK"},{"Type":[2,5,4,7],"Value":"Islamabad"}],"ExtraNames":null}`)
}

func TestCallUnknownAuthority(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: url.QueryEscape(string(testCerts["niko"]["tls.crt"])),
			},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "certificate signed by unknown authority")
}

func TestCallMissingClientCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "client certificate is missing")
}

func TestCallInvalidClientCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: `-----BEGIN%20CERTIFICATE-----%0Ablahblohbleh%3D%3D%0A-----END%20CERTIFICATE-----%0A`,
			},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "invalid client certificate")
}
