package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	"strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function to save our struct in DataStore (not reliable)
func saveStruct(plaint []byte, ourmac []byte, ourenc []byte, ouruuid userlib.UUID) (err error) {
	// Find amount of bytes to pad
	garbagebytes := 16 - len(plaint)%16
	// Iterate through all bytes
	for i := 0; i < garbagebytes; i++ {
		// Add new byte until multiple of 16
		plaint = append(plaint, byte(garbagebytes))
	}
	// Encrypt the data
	ourencnew := userlib.SymEnc(ourenc, userlib.RandomBytes(16), plaint)
	// Then HMAC (encrypt then hmac method)
	ourmacnew, throwerror := userlib.HMACEval(ourmac[:16], ourencnew)
	// If error is thrown
	if throwerror != nil {
		// Returh error
		return throwerror
	} else {
		// Otherwise, marshal the struct
		marshalstruct, throwerror := json.Marshal(&VerifyStruct{ourmacnew, ourencnew})
		// userlib.DebugMsg("%s\n", marshalstruct)
		// If marshal error
		if throwerror != nil {
			// Return error
			return throwerror
		} else {
			// Otherwise, place it in DataStore
			userlib.DatastoreSet(ouruuid, marshalstruct)
			// End call
			return nil
		}
	}
}

// Struct for keys required for users
type Credentials struct {
	// Salt for password
	PassSalt []byte
	// Encrypted user struct
	UserStructEnc []byte
	// Verification
	Check []byte
	// Salt for Verificiation
	VerificationSalt []byte
	// DataStore sign check
	CheckDS []byte
	// HMAC of Struct
	HMACStruct []byte
	// Verification Salt
	SaltVerify []byte
}

// Struct for verification
type VerifyStruct struct {
	// Verification
	Verification []byte
	// Encrypted Data
	InfoEnc []byte
}

// User is the structure definition for a user record.
type User struct {
	// Username
	Username string
	// MAC
	KeyMac []byte
	// Parent key
	KeyParent []byte
	// UUID for file
	FileUUID uuid.UUID
	// Key for signature
	KeySign userlib.DSSignKey
	// User uuid (for linking purposes)
	UuidUser uuid.UUID
	// Decryption key
	KeyDec userlib.PKEDecKey
	// Encryption key
	KeyEnc []byte
}

// type UserCred struct {
//	ourenckey []byte
//	ourmackey []byte
//	sigkey []byte
//	veruuid uuid.UUID
//	ispar int
//	check bool
//}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Credential struct
	var userstruct Credentials
	// User struct
	var userdata User
	// Pointer to user struct
	userdataptr = &userdata
	// Hashed username
	ourhash := userlib.Hash([]byte(username))
	// UUID for user
	var ouruuiduser uuid.UUID
	// Change bytes to the UUID
	for counter := range ouruuiduser {
		ouruuiduser[counter] = ourhash[counter]
	}
	// Username and password cant be empty
	if username == "" || password == "" {
		// Otherwise, error
		return nil, errors.New("Can't have empty credentials!")
	} else {
		// Get user for datastore
		_, exist := userlib.DatastoreGet(ouruuiduser)
		// If user exists
		if exist == true {
			// Throw in an error
			return nil, errors.New("User exists!")
		} else {
			// Otherwise, create the keys for decryption and encryption
			ourenc, ourdec, throwerror := userlib.PKEKeyGen()
			// Create a random salt for password
			saltrand := userlib.RandomBytes(16)
			// Set uuid of user
			userdata.UuidUser = ouruuiduser
			// Call argon2key for password with given salt
			encpass := userlib.Argon2Key([]byte(password), append(saltrand, []byte(username)...), 64)
			// If key generation does not error
			if throwerror == nil {
				// Begin signature keys
				sign, ver, throwerror := userlib.DSKeyGen()
				// Set username
				userdata.Username = username
				// Set password salt
				userstruct.PassSalt = userlib.RandomBytes(16)
				// Decryption key
				userdata.KeyDec = ourdec
				// Verification set
				userstruct.Check = encpass
				// Set the key for verification and encryption
				if userlib.KeystoreSet("keyenct"+username, ver) != nil || userlib.KeystoreSet(username, ourenc) != nil {
					// Return error if not work
					return nil, errors.New("Key Set error!")
				}
				// Check if Digital signature returned error
				if throwerror != nil {
					// If returned, return error
					return nil, errors.New("DSKeyGen Error!")
				}
				// Create digital signature keys
				sign1, ver1, throwerror := userlib.DSKeyGen()
				// If error is found
				if throwerror != nil {
					// return error
					return nil, errors.New("DSKeyGen Error!")
				}
				// Set Salt for verification
				userstruct.SaltVerify = userlib.RandomBytes(16)
				// Verifying process
				userstruct.VerificationSalt = saltrand
				// Key for the user
				userdata.KeyParent = userlib.RandomBytes(16)
				// Signature for user
				userdata.KeySign = sign
				// Digital Signature of user
				sign2, throwerror := userlib.DSSign(sign1, encpass)
				// Set new signature for digital signature
				userstruct.CheckDS = sign2
				// If error is found from Digital signature
				if throwerror != nil {
					// Return error
					return nil, errors.New("Signature Error!")
				}
				// Set key for digital signature
				if userlib.KeystoreSet("kconf"+username, ver1) != nil {
					// If error found, return error
					return nil, errors.New("Key Set Error!")
				}
				// Create new UUID for user storing
				ouruuid := uuid.New()
				// Hash the key for enc
				ourenckey, throwerror := userlib.HashKDF(userdata.KeyParent[:16], []byte("encf"))
				// If there is an error, keep it
				if throwerror != nil {
				} else {
					// Otherwise, hash the key for mac
					ourmackey, throwerror := userlib.HashKDF(userdata.KeyParent[:16], []byte("macf"))
					// If there is an error, keep it
					if throwerror != nil {
					} else {
						// Otherwise, make a map of strings for the file meta data
						info := make(map[string]ParentFileInfo)
						// Marshal the map
						plaininfo, throwerror := json.Marshal(&info)
						// userlib.DebugMsg("%s\n", plaininfo)
						// If there is an error from the marshal, keep it
						if throwerror != nil {
						} else {
							// Otherwise, save the struct with the given mac and enc keys (along with uuid for identification)
							if saveStruct(plaininfo, ourmackey[:16], ourenckey[:16], ouruuid) != nil {
							} else {
								// Set the mac key to be the AES Block Size Bytes count
								userdata.KeyMac = ourmackey[:16]
								// No error thrown otherwise
								throwerror = nil
							}
						}
					}
				}
				// Do same for encryption key
				userdata.KeyEnc = ourenckey[:16]
				// Set a uuid for the file
				userdata.FileUUID = ouruuid
				// If there was an error from the previous process, throw an error
				if throwerror != nil {
					// throw an error
					return nil, throwerror
				} else {
					// Otherwise, marshal the structs now
					marshstruct, throwerror := json.Marshal(userdataptr)
					// userlib.DebugMsg("%s\n", marshstruct)
					// Use default input for the bytestouuid call (wasn't working for some reason)
					inputval := marshstruct
					// Set the value to be the amount of bytes needed to pad to reach a multiple of 16
					garbagebytes := 16 - len(inputval)%16
					// Now iterate through the count of bytes
					for i := 0; i < garbagebytes; i++ {
						// And append how many bytes required
						inputval = append(inputval, byte(garbagebytes))
					}
					// If an error is thrown from the marshal
					if throwerror != nil {
						// return an error
						return nil, errors.New("Marshal Error!")
					}
					// Now use the SymEnc function to encrypt the struct
					symenc := userlib.SymEnc(userlib.Argon2Key([]byte(password), append(userstruct.PassSalt, []byte(username)...), 16), userlib.RandomBytes(16), inputval)
					// Then, MAC it using the Encrypt-then-MAC technique
					ourhmac, throwerror := userlib.HMACEval(userlib.Argon2Key([]byte(password), append(userstruct.SaltVerify, []byte(username)...), 16)[:16], symenc)
					// Set the encrypted struct within the user struct
					userstruct.UserStructEnc = symenc
					// If an error was not found from calling HMACEval
					if throwerror == nil {
						// Set the new HMAC of the struct for the user
						userstruct.HMACStruct = ourhmac
						// Marshal the userstruct
						marshalstr, throwerror := json.Marshal(&userstruct)
						// userlib.DebugMsg("%s\n", marshalstr)
						// If error is found
						if throwerror != nil {
							// Return the error
							return nil, errors.New("Marshal Error!")
						} else {
							// Otherwise, set the marshal within the DataStore
							userlib.DatastoreSet(ouruuiduser, marshalstr)
							// Return the pointer to it finally
							return userdataptr, nil
						}
					} else {
						// Otherwise, return an error
						return nil, throwerror
					}
				}
			} else {
				// Otherwise, return an error
				return nil, errors.New("Error starting user!")
			}
		}
	}
}

// func checkusercred(username string, password string) (err error) {
//	if username == "" || password == "" {
//		return errors.New("Credentials incorrect")
//	}
//	msg, throwerror := userlib.HashKDF(username, password)
//	if userlib.HashKDF(username, password) == nil {
//		return nil
//	} else {
//		return errors.New("Hash error")
//	}
//	ret, exist := userlib.DatastoreGet(msg)
//	if exist == true {
//		return nil
//	} else {
//		return errors.New("Incorrect username/password")
//	}
//	var userstruct Credentials
//	if json.Unmarshal(ret, &Credentials) == nil {
// 		userlib.DebugMsg("%v\n", Credentials)
//		return nil
//	} else {
//		return errors.New("Unmarshal error")
//	}
//	if Credentials != nil {
//		return nil
//	}
//}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	// First of all, hash username to check for value within datastore
	hashuser := userlib.Hash([]byte(username))
	// Create the user struct
	var userdata User
	// Assign variable to pointer
	userdataptr = &userdata
	// Set useruuid
	var ouruuiduser uuid.UUID
	// call bytestouuid
	for counter := range ouruuiduser {
		ouruuiduser[counter] = hashuser[counter]
	}
	// Now find the user with the given username
	getstruct, exist := userlib.DatastoreGet(ouruuiduser)
	// If no user found
	if exist == false {
		// Return an error
		return nil, errors.New("Data Get Error!")
	} else {
		// Otherwise, continue and set the struct for the credentials needed to retrieve the credentials of the user
		var userkeyinfo Credentials
		// Unmarshal the struct
		if json.Unmarshal(getstruct, &userkeyinfo) != nil {
			// userlib.DebugMsg("%v\n", userkeyinfo)
			// Return an error if found
			return nil, errors.New("Unmarshal Error!")
		} else {
			// Otherwise, get the key for the user from keystoreget
			ourkey, exist := userlib.KeystoreGet("kconf" + username)
			// If such a key does indeed exist
			if exist == true {
				// Verify that the Digital Signatures indeed match to what is expected
				if userlib.DSVerify(ourkey, userkeyinfo.Check, userkeyinfo.CheckDS) != nil {
					// Return an error if not
					return nil, errors.New("Verification Error!")
				}
				// Now call argon2key with the specified salt to be able to verify the password
				verification := userlib.Argon2Key([]byte(password), append(userkeyinfo.VerificationSalt, []byte(username)...), (256 / 4))
				// Check each byte
				for i := 0; i < (256 / 4); i++ {
					// that they match
					if userkeyinfo.Check[i] != verification[i] {
						// Otherwise, return an error
						return nil, errors.New("Password incorrect!")
					}
				}
				// Now, evaluate the HMAC
				ourhmac, throwerror := userlib.HMACEval(userlib.Argon2Key([]byte(password), append(userkeyinfo.SaltVerify, []byte(username)...), 16)[:16], userkeyinfo.UserStructEnc)
				// If error is not found from HMACEval
				if throwerror == nil {
					// Check if the HMACs match to each other
					if userlib.HMACEqual(ourhmac, userkeyinfo.HMACStruct) {
						// Decrypt the info to get the struct of the user
						userplaint := userlib.SymDec(userlib.Argon2Key([]byte(password), append(userkeyinfo.PassSalt, []byte(username)...), 16), userkeyinfo.UserStructEnc)
						// Now unpad the given struct
						remuserplaint := userplaint[:len(userplaint)-int(userplaint[len(userplaint)-1])]
						// Unmarshal the struct
						if json.Unmarshal(remuserplaint, userdataptr) == nil {
							// userlib.DebugMsg("%v\n", userdataptr)
							// Return pointer if unmarshal worked correctly
							return userdataptr, nil
						} else {
							// Otherwise, return error
							return nil, errors.New("Unmarshal error!")
						}
					} else {
						// Otherwise, return error
						return nil, errors.New("User info taken!")
					}
				} else {
					// Otherwise, return error
					return nil, errors.New("MAC error!")
				}
			} else {
				// Otherwise, return error
				return nil, errors.New("Key get error!")
			}
		}
	}
}

// Function that will update each part of the file assigned
func partUpdate(ouruuid uuid.UUID, oursalt []byte, partpack []uuid.UUID) (err error) {
	// First of all, hash the salt with the given random input for encryption use
	ourenc, throwerror := userlib.HashKDF(oursalt[:16], []byte("encpart"))
	// If an error is found
	if throwerror != nil {
		// Return error
		return throwerror
	} else {
		// Otherwise, hash the salt with the given random input for mac use
		ourmac, throwerror := userlib.HashKDF(oursalt[:16], []byte("macpart"))
		// If an error is found
		if throwerror != nil {
			// Return error
			return throwerror
		} else {
			// Otherwise, marshal the new information for the part
			ourmarshal, throwerror := json.Marshal(&InfoPart{partpack})
			// userlib.DebugMsg("%s\n", ourmarshal)
			// If error from marshal is found
			if throwerror != nil {
				// Return error
				return throwerror
			}
			// Otherwise, return by calling savestruct to finally update the part entirely.
			return saveStruct(ourmarshal, ourmac[:16], ourenc[:16], ouruuid)
		}
	}
}

// Helper function to save struct and check for MAC
func helper(partlsn int, ouruuid uuid.UUID, oursalt []byte, data []byte, save bool) (dataret []byte, err error) {
	// Initially, hash the salt with the random input for Encryption use
	ourenc, throwerror := userlib.HashKDF(oursalt[:16], []byte(strconv.Itoa(partlsn)))
	// If error is thrown
	if throwerror != nil {
		// Return error
		return nil, throwerror
	} else {
		// Initially, hash the salt with the random input for MAC use
		ourmac, throwerror := userlib.HashKDF(oursalt[:16], []byte(strconv.Itoa(partlsn)))
		// If error is thrown
		if throwerror != nil {
			// Return error
			return nil, throwerror
		} else {
			// If we're attempting to save a struct
			if save == true {
				// Save the struct
				throwerror := saveStruct(data, ourmac[:16], ourenc[:16], ouruuid)
				// Return any errors from savestruct if need be
				return nil, throwerror
			} else {
				// Otherwise, Check the MAC of the given credentials
				dataret, throwerror := MacCheck(ourmac[:16], ourenc[:16], ouruuid)
				// Return any errors from the MACCheck if need be
				return dataret, throwerror
			}
		}
	}
}

// Helper function to check for connection of Sharer
// func helper1(ouruuid uuid.UUID, data []byte) (err error) {
// 	ret, exist := userlib.DatastoreGet(ouruuid)
// 	if exist == false {
//		return errors.New("Get error!")
//	} else {
//		var Shares Sharee
//		if json.Unmarshal(ret, &Shares) == nil {
// userlib.DebugMsg("%v\n", Shares)
//			return errors.New("Unmarshal error!")
//		} else {
//			if Shares.ConnectionS == ouruuid {
//				return nil
//			}
//		}
//	}
//	return
//}

// Function that returns all the information of the given file information struct
func (userdata *User) RetFileInfo(fileinfo ParentFileInfo) (seed []byte, location uuid.UUID, err error) {
	// If the given fileinformation is not for a parent
	if fileinfo.ParentIf == -1 {
		// Get the information of the file that the user can get as a person that gets the information shared
		ourstr, exist := userlib.DatastoreGet(fileinfo.ConnectionS)
		// If user does not exist
		if exist == false {
			// Return error
			return nil, uuid.New(), errors.New("DS get error!2")
		}
		// Create a struct for the sharee to store for future credential usage with the file
		var Shares Sharee
		// Create a struct for a certificate
		var certificate Certificate
		// Unmarshal the information to the sharee struct
		if json.Unmarshal(ourstr, &Shares) != nil {
			// userlib.DebugMsg("%v\n", Shares)
			// If error found, return it
			return nil, uuid.New(), errors.New("Unmarshal Error!")
		}
		// Otherwise, check if the request for the file is valid
		req, throwerror := ReqCheck(userdata.KeyDec, Shares.Sharer, Shares.AccessToken)
		// If error is thrown from checking the request
		if throwerror != nil {
			// Return the error
			return nil, uuid.New(), throwerror
		} else {
			// Otherwise, create a new error for use later
			throwerror1 := errors.New("")
			// Hash the given Verification request for MAC usage later
			ourmac, throwerror := userlib.HashKDF(req.VerifCheck, []byte(req.LinkUUID.String()))
			// If error is found
			if throwerror != nil {
				// return an empty certificate with the given error
				throwerror1 = throwerror
			} else {
				// Hash the given Verification request for encryption usage later
				ourhash, throwerror := userlib.HashKDF(req.VerifCheck, []byte(req.LinkUUID.String()))
				// If error is found
				if throwerror != nil {
					// return an empty certificate with the given error
					throwerror1 = throwerror
				} else {
					// Otherwise, check the MACs
					verinfo, throwerror := MacCheck(ourmac[:16], ourhash[:16], req.LinkUUID)
					// If error is not found from the check
					if throwerror == nil {
						// Unmarshal the information into the certificate struct
						throwerror1 = json.Unmarshal(verinfo, &certificate)
						// userlib.DebugMsg("%v\n", certificate)
					} else {
						// Otherwise, return an empty certificate with the given error
						throwerror1 = throwerror
					}
				}
			}
			// Return seed with the position of the file part along with the error (if any)
			return certificate.Seed, certificate.PointPart, throwerror1
		}
	} else {
		// Lastly, get the file information of the owner
		ourstr, exist := userlib.DatastoreGet(fileinfo.ConnectionO)
		// If it is not found
		if exist == false {
			// Return an error
			return nil, uuid.New(), errors.New("DS get error!3")
		}
		// Otherwise, create a struct for the owner's credential's assosciation with the file
		var OwnerS Owner
		// Unmarshal into a struct
		if json.Unmarshal(ourstr, &OwnerS) != nil {
			// userlib.DebugMsg("%v\n", OwnerS)
			// If error is found, return error
			return nil, uuid.New(), errors.New("Unmarshal Error!")
		} else {
			// Otherwise, return the seed with the position of the file part
			return OwnerS.Seed, OwnerS.PointPart, nil
		}
	}
}

// Helper function to check for connection of Owner
// func helper2(ouruuid uuid.UUID, data []byte) (err error) {
// 	ret, exist := userlib.DatastoreGet(ouruuid)
// 	if exist == false {
//		return errors.New("Get error!")
//	} else {
//		var Shares Sharee
//		if json.Unmarshal(ret, &Shares) == nil {
//			return errors.New("Unmarshal error!")
//		} else {
//			if Shares.ConnectionO == ouruuid {
//				return nil
//			}
//		}
//	}
//	return
//}

// Struct for request
type Req struct {
	// UUID for linking with requests
	LinkUUID uuid.UUID
	// Verification Check for requests
	VerifCheck []byte
}

// Information for the entire file
type ParentFileInfo struct {
	// Check if for parent
	ParentIf int
	// Verification check for requests
	VerifCheck []byte
	// Connection to owner credentials
	ConnectionO uuid.UUID
	// Connection to the requestor credentials
	ConnectionS uuid.UUID
}

type Owner struct {
	PointPart  uuid.UUID // File Part's location
	Seed       []byte    // Seed for Owner
	GiveAccess map[string]struct {
		LinkUUID   uuid.UUID
		VerifCheck []byte
	} // people given access to
	ConnectionO uuid.UUID // Connection UUID for owner
}

type Sharee struct {
	Sharer      string    // Sharer's username
	ConnectionS uuid.UUID // Connection UUID for whoever got share
	AccessToken uuid.UUID // Accesstoken
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	// Set initial error
	err = nil
	// Set helper error
	var throwerror error
	// Set map of strings for the file information
	var alloc map[string]ParentFileInfo
	// Check that the MAC provided is correct
	verinfo, throwerror1 := MacCheck(userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
	// If error found
	if throwerror1 != nil {
		// Return an allocation of nil
		alloc = nil
		// Return the error
		throwerror = throwerror1
	} else {
		// Otherwise, create helper file info
		var fileinfo map[string]ParentFileInfo
		// Unmrashal the file info
		// If error found
		if json.Unmarshal(verinfo, &fileinfo) != nil {
			// userlib.DebugMsg("%v\n", fileinfo)
			// Return an allocation of nil
			alloc = nil
			// Set return error
			throwerror = errors.New("unmarshal error!")
		} else {
			// Otherwise, set allocation to the file info
			alloc = fileinfo
			// Set return error to nil
			throwerror = nil
		}
	}
	// If error found
	if throwerror != nil {
		// Return error
		return throwerror
	} else {
		// Otherwise, get the file information
		fileinfo, exist := alloc[filename]
		// If it does not exist
		if exist == false {
			// Create new struct for file info
			var fileinf ParentFileInfo
			// Create Owner struct
			var OwnerS Owner
			// Set Owner and Sharee UUID for struct connection
			fileinf.ConnectionO = uuid.New()
			fileinf.ConnectionS = uuid.New()
			// Set Seed for Sharee
			OwnerS.Seed = userlib.RandomBytes(16)
			// Set Helper location for our partition
			OwnerS.PointPart = uuid.New()
			// Create a request struct for access
			OwnerS.GiveAccess = make(map[string]struct {
				LinkUUID   uuid.UUID
				VerifCheck []byte
			})
			// Set connection UUID
			OwnerS.ConnectionO = fileinf.ConnectionO
			// Marshal our Sharee struct
			ret, throwerror := json.Marshal(OwnerS)
			// userlib.DebugMsg("%s\n", ret)
			// If error found
			if throwerror != nil {
				// return that error
				return throwerror
			} else {
				// Otherwise, Set the Owner struct
				userlib.DatastoreSet(OwnerS.ConnectionO, ret)
			}
			// Set struct to be the owner's
			fileinf.ParentIf = 1
			// Set verification key
			fileinf.VerifCheck = userlib.RandomBytes(16)
			// Assign file information
			alloc[filename] = fileinf
			// Create new partition
			initpart := make([]uuid.UUID, 1)
			// Set new UUID for first partition
			initpart[0] = uuid.New()
			// Update the partition and check for error
			if partUpdate(OwnerS.PointPart, OwnerS.Seed, initpart) == nil {
				// If error does not exist, call helper to see if information is correct
				_, throwerror = helper(0, initpart[0], OwnerS.Seed, data, true)
				// If error found
				if throwerror != nil {
					// return error
					throwerror = errors.New("Update Error!")
				} else {
					// Otherwise, set error to nil
					throwerror = nil
				}
			} else {
				// Otherwise, throw error
				throwerror = errors.New("Update Error!")
			}
		} else {
			// Otherwise, get the file information from our derived fileinfo
			seed, PointPart, throwerror := userdata.RetFileInfo(fileinfo)
			// If error presenet
			if throwerror != nil {
				// Leave be, will be returned later
			} else {
				// Otherwise, get the partitions of our file
				parts, throwerror := callPartfile(PointPart, seed)
				// If error does not exist
				if throwerror == nil {
					// Iterate through all parts
					for x, part := range parts {
						// Leave x be
						x = x
						// Delete every part
						userlib.DatastoreDelete(part)
					}
					// Get first part
					initpartn := make([]uuid.UUID, 1)
					// Set first part's UUID
					initpartn[0] = uuid.New()
					// Check if updating the part returns an error
					if partUpdate(PointPart, seed, initpartn) != nil {
						// If it does, return error
						throwerror = errors.New("Update Error!")
					} else {
						// Otherwise, call helper to check if error pops up for retrieving file info
						_, throwerror = helper(0, initpartn[0], seed, data, true)
					}
				} else {
					// Otherwise, return error
					return throwerror
				}
			}
		}
		// If error is found
		if throwerror != nil {
			// Return error
			return throwerror
		} else {
			// Otherwise, marshal our allocation
			newalloc, throwerror := json.Marshal(&alloc)
			// userlib.DebugMsg("%s\n", newalloc)
			// If error is found
			if throwerror != nil {
				// Return the error
				return throwerror
			} else {
				// Otherwise, save our newly formed struct for file information
				return saveStruct(newalloc, userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
			}
		}
	}
}

// Function that checks if the given MAC is correct or not
func MacCheck(ourmac []byte, ourenc []byte, ouruuid userlib.UUID) ([]byte, error) {
	// Get the DS struct to verify MAC from DataStore
	dsget, exist := userlib.DatastoreGet(ouruuid)
	// If it does exist
	if exist == true {
		// Otherwise, create a new struct to unmarshal
		var dsstruct VerifyStruct
		// If the unmarshal does return an error
		if json.Unmarshal(dsget, &dsstruct) != nil {
			// userlib.DebugMsg("%v\n", dsstruct)
			// Return an unmarshal error
			return nil, errors.New("Unmarshal error!")
		} else {
			// Otherwise, evaluate the given information to see if MAC is indeed correct
			rethmac, throwerror := userlib.HMACEval(ourmac[:16], dsstruct.InfoEnc)
			// If error exists
			if throwerror != nil {
				// Return HMAC error
				return nil, errors.New("HMAC check error")
			}
			// If the given HMACs are not equivalent
			if userlib.HMACEqual(rethmac, dsstruct.Verification) == false {
				// Return an HMAC error
				return nil, errors.New("HMAC check error")
			} else {
				// Otherwise, decrypt to plaintext
				decinf := userlib.SymDec(ourenc, dsstruct.InfoEnc)
				// and return
				return decinf[:len(decinf)-int(decinf[len(decinf)-1])], nil
			}
		}
	} else {
		// Otherwise, return an error
		return nil, errors.New("Not found!")
	}
}

// Helper to allow requests
func AccRequest(accept string, sign userlib.DSSignKey, request Req, ouruuid uuid.UUID) (err error) {
	// Marshal the request struct that we passed in
	marshinfo, throwerror := json.Marshal(&request)
	// userlib.DebugMsg("%s\n", marshinfo)
	// If error does not exist
	if throwerror == nil {
		// Continue and get the encryption key
		ourenc, exist := userlib.KeystoreGet(accept)
		// If it exists
		if exist == true {
			// Continue and get the encrypted information
			infenc, throwerror := userlib.PKEEnc(ourenc, marshinfo)
			// IF encryption contains error
			if throwerror != nil {
				// Return error
				return throwerror
			} else {
				// Otherwise, call DSSign
				DS, throwerror := userlib.DSSign(sign, infenc)
				// If it contains no errors
				if throwerror == nil {
					// Masrshal the verification struct
					newmarsh, throwerror := json.Marshal(&VerifyStruct{DS, infenc})
					// userlib.DebugMsg("%s\n", newmarsh)
					// If no marshal errors are returned
					if throwerror == nil {
						// Set the new marshalled struct using our new uuid
						userlib.DatastoreSet(ouruuid, newmarsh)
						// return nil to end call
						return nil
					} else {
						// Otherwise, return error
						return throwerror
					}
				} else {
					// Otherwise, return error
					return throwerror
				}
			}
		} else {
			// Otherwise, return error
			return errors.New("Get Error!")
		}
	} else {
		// Otherwise, return error
		return throwerror
	}
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Set initial error
	err = nil
	// Set helper error
	var throwerror error
	// Create metadata for the file information to use
	var alloc map[string]ParentFileInfo
	// Check the given Mac is correct
	verinfo, throwerror1 := MacCheck(userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
	// If an error does not exist
	if throwerror1 == nil {
		// Then create a helper metadata holder for return
		var fileinfo map[string]ParentFileInfo
		// Unmarshal the given file information
		if json.Unmarshal(verinfo, &fileinfo) != nil {
			// userlib.DebugMsg("%v\n", fileinfo)
			// Set the return allocation to nil
			alloc = nil
			// Return error message
			throwerror = errors.New("unmarshal error!")
		} else {
			// Set the return allocation to the retrieved file
			alloc = fileinfo
			// Return error message
			throwerror = nil
		}
	} else {
		// Otherwise, if error does exist
		// Set the return allocation to nil
		alloc = nil
		// Return error message
		throwerror = throwerror1
	}
	// If error doesn't exist
	if throwerror == nil {
		// Get the file information
		fileinfo, exist := alloc[filename]
		// If it doesn't exist
		if exist == false {
			// Return error
			return errors.New("File not found!")
		} else {
			// Otherwise, return all info of file
			decenckey, partfile, throwerror := userdata.RetFileInfo(fileinfo)
			// If error exists
			if throwerror != nil {
				// Return error
				return throwerror
			} else {
				// Get the current partitions of the given file, use decenckey to get raw data.
				partitions, throwerror := callPartfile(partfile, decenckey)
				// If error exists
				if throwerror != nil {
					// Return error
					return throwerror
				} else {
					// Create a new uuid for the new partition
					newuuid := uuid.New()
					// Call helper to see if information given is correct
					_, throwerror = helper(len(partitions), newuuid, decenckey, data, true)
					// If error does not exist
					if throwerror == nil {
						// Append the new partition to the file information, helped with the new uuid
						partitions = append(partitions, newuuid)
						// Update the partition, check if error exist
						// If error doesnt exist
						if partUpdate(partfile, decenckey, partitions) == nil {
							// Return nil
							return nil
						} else {
							// Otherwise, return error
							return err
						}
					} else {
						// Otherwise, if error does exist
						// Return error
						return throwerror
					}
				}
			}
		}
	} else {
		// Otherwise, if error does exist
		// Return error
		return throwerror
	}
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	// Set initial error for later use
	err = nil
	// Set error for later use
	var throwerror error
	// Create a new map of strings for the file information
	var alloc map[string]ParentFileInfo
	// Check for MAC
	verinfo, throwerror1 := MacCheck(userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
	// If error is not found
	if throwerror1 == nil {
		// Create a map of strings for the file information
		var fileinfo map[string]ParentFileInfo
		// Unmarshal the information to the file info
		if json.Unmarshal(verinfo, &fileinfo) != nil {
			// userlib.DebugMsg("%v\n", fileinfo)
			// If error is found, return error
			alloc = nil
			throwerror = errors.New("unmarshal error!")
		} else {
			// Otherwise, set alloc to the file information
			alloc = fileinfo
			// Set return error to nil
			throwerror = nil
		}
	} else {
		// Otherwise, return error
		alloc = nil
		throwerror = throwerror1
	}
	// if no error found
	if throwerror == nil {
		// Set fileinfo of the respective file's name
		fileinfo, exist := alloc[filename]
		// If it does not exist
		if exist == false {
			// return error
			return nil, errors.New("No such file!")
		} else {
			// Get file information of the given file
			enckey, filepoint, throwerror := userdata.RetFileInfo(fileinfo)
			// If error not found
			if throwerror == nil {
				// Get the file's part of the given location
				partition, throwerror := callPartfile(filepoint, enckey)
				// If error found
				if throwerror != nil {
					// Otherwise, return error
					return nil, throwerror
				}
				// Iterate through all parts
				for counter, mini_partition := range partition {
					// Call helper to get file information
					fileinfo, throwerror := helper(counter, mini_partition, enckey, nil, false)
					// If error not found
					if throwerror == nil {
						// Append information to data
						dataBytes = append(dataBytes, fileinfo...)
					} else {
						// Otherwise, return error
						return nil, throwerror
					}
				}
				// Otherwise, return
				return
			} else {
				// Otherwise, return error
				return nil, throwerror
			}
		}
	} else {
		// Otherwise, return error
		return nil, throwerror
	}
}

// Struct for Certificate information
type Certificate struct {
	// UUID for the part of the file
	PointPart uuid.UUID
	// Seed for certificate
	Seed []byte
}

// Part information struct
type InfoPart struct {
	// Part's uuid
	Part []uuid.UUID
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	// If username is the same as the recipient
	if userdata.Username == recipient {
		// Throw error
		return accessToken, errors.New("can't share file with already shared recipients!")
	} else {
		// Otherwise, set initial error for later use
		err = nil
		// Set error for later use
		var throwerror error
		// Map of fileinformation
		var alloc map[string]ParentFileInfo
		// Check the given MAC
		verinfo, throwerror1 := MacCheck(userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
		// If error is found
		if throwerror1 != nil {
			// Return error
			alloc = nil
			// Set return error to the error from our MacCheck
			throwerror = throwerror1
		} else {
			// Otherwise, create another map of file information
			var fileinfo map[string]ParentFileInfo
			// Unmarshal the struct
			if json.Unmarshal(verinfo, &fileinfo) == nil {
				// userlib.DebugMsg("%v\n", fileinfo)
				// If no error found, move on
				alloc = fileinfo
				// Set error to nil
				throwerror = nil
			} else {
				// Otherwise, return an error
				alloc = nil
				// Set return error to an unmarshal error
				throwerror = errors.New("unmarshal error!")
			}
		}
		// If an error exists from previous parts
		if throwerror != nil {
			// Return an error
			return accessToken, throwerror
		}
		// Else, get the file information for the given part
		fileinfo, exist := alloc[filename]
		// If it does not exist
		if exist == false {
			// Return an error
			return accessToken, errors.New("no filename found!")
		} else {
			// Otherwise, check if it is for parent
			if fileinfo.ParentIf == 1 {
				// If so, get the credentials information from Owner
				ourstr, exist := userlib.DatastoreGet(fileinfo.ConnectionO)
				// If it does not exist
				if exist == false {
					// Return an error
					return accessToken, errors.New("DS get error1!")
				}
				// Set struct for owner information
				var OwnerS Owner
				// Unmarshal info to struct
				if json.Unmarshal(ourstr, &OwnerS) != nil {
					// userlib.DebugMsg("%v\n", OwnerS)
					// If struct error found, return error
					return accessToken, errors.New("Unmarshal Error!")
				}
				// Else, continue with the given access of the recipient
				_, exist = OwnerS.GiveAccess[recipient]
				// If already given access
				if exist == true {
					// No need to give access again
					return accessToken, errors.New("can't share again1!")
				}
				// Else, generate new uuid for location to new file part
				partitionpos := uuid.New()
				// Create mash for encryption purposes
				oure, throwerror := userlib.HashKDF(fileinfo.VerifCheck, []byte(partitionpos.String()))
				// Create mash for MAC purposes
				ourm, throwerror := userlib.HashKDF(fileinfo.VerifCheck, []byte(partitionpos.String()))
				// Marshal the given information to the Certificate info
				plain, throwerror := json.Marshal(&Certificate{OwnerS.PointPart, OwnerS.Seed})
				// userlib.DebugMsg("%s\n", plain)
				// If marshal error found
				if throwerror != nil {
					// Move on
				} else {
					// Otherwise, save the struct and see if any error is found
					throwerror = saveStruct(plain, ourm[:16], oure[:16], partitionpos)
				}
				// If error is found
				if throwerror != nil {
					// Return error
					return uuid.New(), throwerror
				}
				// Assign a new request struct for the recipient access
				OwnerS.GiveAccess[recipient] = Req{partitionpos, fileinfo.VerifCheck}
				// Set new accesstoken for it
				accessToken = uuid.New()
				// And now accept the request
				throwerror = AccRequest(recipient, userdata.KeySign, Req{partitionpos, fileinfo.VerifCheck}, accessToken)
				// If any error thrown from these requests
				if throwerror != nil {
					// Return error
					return uuid.New(), throwerror
				} else {
					// Otherwise, get file information
					alloc[filename] = fileinfo
					// Marshal the given information now
					decenckey, throwerror := json.Marshal(&alloc)
					// userlib.DebugMsg("%s\n", decenckey)
					// If error is not found from marshal
					if throwerror == nil {
						// Marshal the Owner's file information credentials struct
						ret, throwerror := json.Marshal(OwnerS)
						// userlib.DebugMsg("%s\n", ret)
						// If marshal error is found
						if throwerror != nil {
							// return error
							return accessToken, throwerror
						}
						// Otherwise, set the struct of the owner
						userlib.DatastoreSet(fileinfo.ConnectionO, ret)
						// Lastly, return the access token with the given struct
						return accessToken, saveStruct(decenckey, userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
					} else {
						// Otherwise, return error
						return accessToken, errors.New("Enc fail!")
					}
				}
			} else {
				// Get the Sharee's file information credentials struct
				ourstr, exist := userlib.DatastoreGet(fileinfo.ConnectionS)
				// If error is found
				if exist == false {
					// return error
					return uuid.New(), errors.New("DS get error4!")
				}
				// Otherwise, create struct for use
				var Shares Sharee
				// Unmarshal the information to the struct
				if json.Unmarshal(ourstr, &Shares) != nil {
					// userlib.DebugMsg("%v\n", Shares)
					// If unmarshal error found, return error
					return uuid.New(), errors.New("Marshal error!")
				}
				// else, check for the request's eligibility
				verify, throwerror := ReqCheck(userdata.KeyDec, Shares.Sharer, Shares.AccessToken)
				// If no error found
				if throwerror == nil {
					// Create new accesstoken
					accessToken = uuid.New()
					// Return accesstoken with the accepted request information
					return accessToken, AccRequest(recipient, userdata.KeySign, verify, accessToken)
				} else {
					// Otherwise, return an error
					newuuid := uuid.New()
					return newuuid, throwerror
				}
			}
		}
	}
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	// Set initial variable for error
	var throwerror error
	// Set initial file information map
	var alloc map[string]ParentFileInfo
	// Call Mac helper to see if info is correct
	verinfo, throwerror1 := MacCheck(userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
	// If error returned
	if throwerror1 != nil {
		// Set return allocation to nil
		alloc = nil
		// Set return error
		throwerror = throwerror1
	} else {
		// Set helper fileinfo map
		var fileinfo map[string]ParentFileInfo
		// Unmarshal our information
		// If error returned
		if json.Unmarshal(verinfo, &fileinfo) != nil {
			// userlib.DebugMsg("%v\n", fileinfo)
			// Set return allocation to nil
			alloc = nil
			// Set return error
			throwerror = errors.New("unmarshal error!")
		} else {
			// Otherwise, set fileinfo to be the new allocation
			alloc = fileinfo
			// Don't return an error
			throwerror = nil
		}
	}
	// If an error has been assigned
	if throwerror != nil {
		// Return that error
		return throwerror
	} else {
		// Otherwise, check if the filename exists in our map
		_, exist := alloc[filename]
		// If not a parent or doesn't exist
		if alloc[filename].ParentIf == -1 || exist == false {
			// Create new file
			var receipientfileinfo ParentFileInfo
			// Set that not a parent
			receipientfileinfo.ParentIf = -1
			// Set new UUID for Sharee
			receipientfileinfo.ConnectionS = uuid.New()
			// Set new UUID for Parent
			receipientfileinfo.ConnectionO = uuid.New()
			// Create new sharee struct
			var Shareestr Sharee
			// Set sharer name
			Shareestr.Sharer = sender
			// Set its accesstoken
			Shareestr.AccessToken = accessToken
			// Set the UUID for connection
			Shareestr.ConnectionS = receipientfileinfo.ConnectionS
			// Marshal our new sharee struct
			allocfile, throwerror := json.Marshal(Shareestr)
			// userlib.DebugMsg("%s\n", allocfile)
			// If error exists
			if throwerror != nil {
				// Return the error
				return throwerror
			}
			// Otherwise, set the new sharee struct
			userlib.DatastoreSet(Shareestr.ConnectionS, allocfile)
			// Get the file information
			_, _, throwerror = userdata.RetFileInfo(receipientfileinfo)
			// If error found
			if throwerror != nil {
				// Throw error
				return throwerror
			} else {
				// Otherwise, set new filename allocation
				alloc[filename] = receipientfileinfo
				// Marshal the new struct
				allocfile, throwerror := json.Marshal(&alloc)
				// userlib.DebugMsg("%s\n", allocfile)
				// If marshal error thrown
				if throwerror != nil {
					// Return an error
					return errors.New("Marshal error!")
				} else {
					// Otherwise, save the new defined structs
					return saveStruct(allocfile, userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
				}
			}
		} else {
			// Otherwise, return an error
			return errors.New("Error!")
		}
	}
}

// Helper function to check for requests
func ReqCheck(deckey userlib.PKEDecKey, info string, ouruuid uuid.UUID) (Req, error) {
	// Create struct for information verification
	var infostruct VerifyStruct
	// Create a request struct
	var req Req
	// Get the digital signature info
	dsget, exist := userlib.DatastoreGet(ouruuid)
	// If it does not exist
	if exist == false {
		// Return an error
		return req, errors.New("Get Error!")
	} else {
		// Otherwise, encrypt the information for signature use
		sign, exist := userlib.KeystoreGet("keyenct" + info)
		// If it does not exist
		if exist == false {
			// Return an error
			return req, errors.New("Get Error!")
		} else {
			// Otherwise, unmarshal the information to the struct
			if json.Unmarshal(dsget, &infostruct) != nil {
				// userlib.DebugMsg("%v\n", infostruct)
				// Return an error if unmarshal error occurs
				return req, errors.New("Unmarsh error!")
			} else {
				// Otherwise, verify that the digital signatures are indeed correct
				if userlib.DSVerify(sign, infostruct.InfoEnc, infostruct.Verification) == nil {
					// Decrypt the given information using our decryption key
					decinf, throwerror := userlib.PKEDec(deckey, infostruct.InfoEnc)
					// If error is not found
					if throwerror == nil {
						// return the request with the unmarshalled struct
						return req, json.Unmarshal(decinf, &req)
					} else {
						// Otherwise, retun the error
						return req, throwerror
					}
				} else {
					// Otherwise, return error
					return req, errors.New("Verification Error!")
				}
			}
		}
	}
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	// Create variable for error
	var throwerror error
	// Get map of strings for file information
	var alloc map[string]ParentFileInfo
	// Check for MACs
	verinfo, throwerror1 := MacCheck(userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
	// If error is found
	if throwerror1 != nil {
		// Return the given error
		alloc = nil
		throwerror = throwerror1
	} else {
		// Otherwise, get map ofstrings for file information
		var fileinfo map[string]ParentFileInfo
		// Unmarshal the data into the given struct
		if json.Unmarshal(verinfo, &fileinfo) != nil {
			// userlib.DebugMsg("%v\n", fileinfo)
			// If error for unmarshal is found, return error
			alloc = nil
			throwerror = errors.New("unmarshal error!")
		} else {
			// Otherwise, assign the file information for use later
			alloc = fileinfo
			throwerror = nil
		}
	}
	// If no error from previous work is found
	if throwerror == nil {
		// Assign the fileinfo for the given file's name
		fileinfo, exist := alloc[filename]
		// Get the file struct using the owner's information
		ourstr, exist := userlib.DatastoreGet(fileinfo.ConnectionO)
		// If error is found
		if exist == false {
			// return an error
			return errors.New("DS get error5!")
		}
		// Otherwise, create a struct for Owner's file information credentials
		var OwnerS Owner
		// Unmarshal the info to the struct
		if json.Unmarshal(ourstr, &OwnerS) != nil {
			// userlib.DebugMsg("%v\n", OwnerS)
			// Return an error if unmarshal error found
			return errors.New("Unmarshal Error!")
		}
		// Get decryption key by using the seed
		decenckey := OwnerS.Seed
		// If error is found
		if exist == false {
			// Return an error
			return errors.New("no filename found!")
		} else {
			// Otherwise, get the user's struct from the target username
			userstruct, exist := OwnerS.GiveAccess[targetUsername]
			// If no such struct exists
			if exist == false {
				// Return an error
				return errors.New("username already does not have access!")
			}
			// Otherwise, create a new seed for the sharee
			OwnerS.Seed = userlib.RandomBytes(16)
			// Get the part of the file by calling the helper
			partition, throwerror := callPartfile(OwnerS.PointPart, decenckey)
			// If any error found
			if throwerror != nil {
				// Return error
				return throwerror
			}
			// Otherwise, delete the struct for the user request info
			userlib.DatastoreDelete(userstruct.LinkUUID)
			// Update part for users to access
			throwerror = partUpdate(OwnerS.PointPart, OwnerS.Seed, partition)
			// if any error found
			if throwerror != nil {
				// return error
				return errors.New("Save Error!")
			}
			// Otherwise, iterate through all parts of file
			for counter, minipartition := range partition {
				// Call the helper to get the file information
				ourstr, throwerror := helper(counter, minipartition, decenckey, nil, false)
				// If any error found
				if throwerror != nil {
					// Return error
					return throwerror
				} else {
					// Otherwise, call the helper for the Owner's file info
					_, throwerror = helper(counter, minipartition, OwnerS.Seed, ourstr, true)
					// If any error found
					if throwerror != nil {
						// Return error
						return throwerror
					}
				}
			}
			// Delete the username from the list of accesses eligible
			delete(OwnerS.GiveAccess, targetUsername)
			// Iterate through all requests
			for _, req := range OwnerS.GiveAccess {
				// Hash the given verification credentials for encryption purposes
				oure, throwerror1 := userlib.HashKDF(req.VerifCheck, []byte(req.LinkUUID.String()))
				// If error is not found
				if throwerror1 == nil {
					// Hash the given verification credentials for MAC purposes
					ourm, throwerror1 := userlib.HashKDF(req.VerifCheck, []byte(req.LinkUUID.String()))
					// If error is found
					if throwerror1 != nil {
						// Return error
						throwerror = throwerror1
					} else {
						// Otherwise, marshal the worked struct
						plain, throwerror1 := json.Marshal(&Certificate{OwnerS.PointPart, OwnerS.Seed})
						// userlib.DebugMsg("%s\n", plain)
						// If marshal error found
						if throwerror1 != nil {
							// return given error
							throwerror = throwerror1
						} else {
							// Otherwise save struct
							throwerror = saveStruct(plain, ourm[:16], oure[:16], req.LinkUUID)
						}
					}
				} else {
					// Otherwise, return error
					return throwerror1
				}
				// If error found
				if throwerror != nil {
					// Otherwise return error
					return throwerror
				}
			}
			// Set the new file information
			alloc[filename] = fileinfo
			// Marshal the given file info struct
			marshfile, throwerror := json.Marshal(&alloc)
			// userlib.DebugMsg("%s\n", marshfile)
			// If error not found
			if throwerror == nil {
				// Save struct
				return saveStruct(marshfile, userdata.KeyMac, userdata.KeyEnc, userdata.FileUUID)
			} else {
				// Otherwise, return an error
				return throwerror
			}
		}
	} else {
		// Otherwise, return an error
		return throwerror
	}
}

// Helper function to get information of the file's requested part
func callPartfile(ouruuid uuid.UUID, verify []byte) ([]uuid.UUID, error) {
	// Create a struct for the file part's info
	var filepart InfoPart
	// Hash the given credential for encryption purposes
	ourenc, throwerror := userlib.HashKDF(verify[:16], []byte("encpart"))
	// If error is found
	if throwerror != nil {
		// Return error
		return nil, throwerror
	} else {
		// Otherwise, Hash the given credential for MAC purposes
		ourmac, throwerror := userlib.HashKDF(verify[:16], []byte("macpart"))
		// If error is found
		if throwerror != nil {
			// Return error
			return nil, throwerror
		} else {
			// Otherwise, check for MAC
			plain, throwerror := MacCheck(ourmac[:16], ourenc[:16], ouruuid)
			// if error is found
			if throwerror != nil {
				// return error
				return nil, throwerror
			} else {
				// otherwise, return file information
				return filepart.Part, json.Unmarshal(plain, &filepart)
			}
		}
	}
}
