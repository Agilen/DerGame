package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"os"
)

type EncryptedProgram struct {
	Name string
	Salt []byte
	// Password string
	Params  []string
	Program []byte
}

//32
func main() {

	var EP EncryptedProgram
	file, err := os.Open("Program0.enc")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()
	data := make([]byte, 64)
	var h []byte
	for {
		_, err := file.Read(data)
		if err == io.EOF {
			break
		}
		h = append(h, data...)
	}
	_, err = asn1.Unmarshal(h, &EP)
	if err != nil {
		fmt.Println(err)
	}
	password := []byte{65, 65, 65, 65}
	BrudForce(password, &EP)

}

func BrudForce(Password []byte, EP *EncryptedProgram) []byte {
	mass := []byte{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57}

	counter := 0
	for i := 0; i < len(mass); i++ {
		Password[0] = mass[i]
		counter++
		for j := 0; j < len(mass); j++ {
			Password[1] = mass[j]
			counter++
			for k := 0; k < len(mass); k++ {
				Password[2] = mass[k]
				counter++
				for l := 0; l < len(mass); l++ {
					Password[3] = mass[l]

					fmt.Println(Decrypt(f(XOR(Pad(Password, 16, 0), EP.Salt)), EP.Program, EP.Salt))
					os.Exit(0)
				}
			}
		}
	}
	fmt.Println(counter)
	return Password
}

func Pad(Password []byte, size int, b byte) []byte {
	for i := len(Password); i < 16; i++ {
		Password = append(Password, byte(0))
	}
	return Password
}

func XOR(pas []byte, salt []byte) (pass []byte) {
	for i := 0; i < len(salt); i++ {
		pass = append(pass, pas[i]^salt[i])
	}
	return pass
}
func f(password []byte) []byte {
	h := sha256.Sum256(password)
	var hash []byte
	for i := 0; i < len(h); i++ {
		hash = append(hash, h[i])
	}
	return hash
}

func Decrypt(key []byte, securemess []byte, salt []byte) (decodedmess []byte, err error) {
	fmt.Println(len(key))
	block, err := aes.NewCipher(key)
	fmt.Println(block.BlockSize())
	if err != nil {
		return
	}

	if len(securemess) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short")
		return
	}

	// securemess = securemess[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, salt)

	stream.XORKeyStream(securemess, securemess)

	decodedmess = securemess
	return
}
