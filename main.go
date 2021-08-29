package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

type EncryptedProgram struct {
	Name     string
	Password []byte
	Salt     []byte
	Programm []byte
}

type Encrypted struct {
	Name    string
	Salt    []byte
	Params  []string
	Program []byte
}

//32
func main() {

	//var EP EncryptedProgram
	var EPOrig Encrypted

	file, err := os.ReadFile("Program0.enc")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	_, err = asn1.Unmarshal(file, &EPOrig)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(EPOrig.Params)
	fmt.Println(len(EPOrig.Params))

	//file, err := os.ReadFile("Hello.enc")
	//if err != nil {
	//	fmt.Println(err)
	//	os.Exit(1)
	//}

	//_, err = asn1.Unmarshal(file, &EP)
	//if err != nil {
	//	fmt.Println(err)
	//}

	// fmt.Println(EP.Password)
	password := []byte{65, 65, 65, 65}

	BrudForceV2(password, &EPOrig)

}
func BrudForceV2(Password []byte, EP *Encrypted) {
	// массив с байтами которые представляют собой символы из  PrintableString
	mass := []byte{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57}

	// полный перебор
	for i := 0; i < len(mass); i++ {
		Password[0] = mass[i]

		for j := 0; j < len(mass); j++ {
			Password[1] = mass[j]

			for k := 0; k < len(mass); k++ {
				Password[2] = mass[k]

				for p := 0; p < len(mass); p++ {
					Password[3] = mass[p]

					pad := Pad(Password, 16, 0)
					xor := XOR(pad, EP.Salt)
					key := Sha(xor)

					dec, _ := DecryptCheck(key, EP.Program[:16*10])
					flag := CheckFile(dec)

					if flag {
						fmt.Println(string(Password))
						prog, err := Decrypt(key, EP.Program[:])
						if err != nil {
							fmt.Println(err)
							os.Exit(0)
						}
						fmt.Println("1")

						os.Remove(EP.Name)
						file, err := os.Create(EP.Name)
						if err != nil {
							fmt.Println(err)
							os.Exit(0)
						}
						fmt.Println("2")
						file.Write(prog)

						file.Close()

						cmd := exec.Command(EP.Name, string(EP.Params[0]+" "+EP.Params[1]))
						stdout, err := cmd.Output()
						if err != nil {
							fmt.Println("err", err)
							os.Exit(0)
						}
						fmt.Println(string(stdout))

					}

				}

			}
		}
	}

}
func BrudForce(Password []byte, EP *EncryptedProgram) {
	// массив с байтами которые представляют собой символы из  PrintableString
	mass := []byte{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57}

	// полный перебор
	for i := 0; i < len(mass); i++ {
		Password[0] = mass[i]

		for j := 0; j < len(mass); j++ {
			Password[1] = mass[j]

			for k := 0; k < len(mass); k++ {
				Password[2] = mass[k]

				for p := 0; p < len(mass); p++ {
					Password[3] = mass[p]

					pad := Pad(Password, 16, 0)
					xor := XOR(pad, EP.Salt)
					key := Sha(xor)

					dec, _ := DecryptCheck(key, EP.Programm[:16*10])
					flag := CheckFile(dec)

					if flag {

						prog, err := Decrypt(key, EP.Programm[:])
						if err != nil {
							fmt.Println(err)
							os.Exit(0)
						}
						os.Remove(EP.Name)
						file, err := os.Create(EP.Name)
						if err != nil {
							fmt.Println(err)
							os.Exit(0)
						}

						file.Write(prog)

						file.Close()

						cmd := exec.Command(EP.Name)
						stdout, err := cmd.Output()
						if err != nil {
							fmt.Println(err)
							os.Exit(0)
						}
						fmt.Println(string(stdout))

					}

				}

			}
		}
	}

}

//Дополняю ключ до нужного размера
func Pad(Password []byte, size int, b byte) []byte {
	for i := len(Password); i < 16; i++ {
		Password = append(Password, byte(0))
	}
	return Password
}

//XOR двух масивов
func XOR(pas []byte, salt []byte) (pass []byte) {
	for i := 0; i < len(salt); i++ {
		pass = append(pass, pas[i]^salt[i])
	}
	if len(pass) != 16 {
		fmt.Println("!16")
		os.Exit(0)
	}
	return pass
}

//Получаю пороль из хеш функции
func Sha(password []byte) []byte {
	h := sha256.Sum256(password)

	return h[:]
}

func DecryptCheck(key []byte, secur []byte) (decodedmess []byte, err error) {
	var securemess []byte
	securemess = append(securemess, secur...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(securemess) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	if len(securemess)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	mode.CryptBlocks(securemess, securemess)

	if err != nil {
		fmt.Println(err)
	}

	decodedmess = securemess
	return
}

func Decrypt(key []byte, securemess []byte) (decodedmess []byte, err error) {
	var decmessage []byte
	decmessage = append(decmessage, securemess...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(securemess) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	if len(decmessage)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	mode.CryptBlocks(decmessage, decmessage)

	if err != nil {
		fmt.Println(err)
	}

	decodedmess = decmessage
	return
}

func CheckFile(prog []byte) bool {
	//4D 5A 90 00 03 00 04 00 00 00 00 00 FF FF 00 00

	check := []byte{0x4D, 0x5A}
	check2 := []byte{0x50, 0x45}
	if !bytes.Equal(check, prog[:len(check)]) {
		return false
	} else if !bytes.Equal(check2, prog[128:130]) {
		return false
	}
	return true
}
