package confz

import (
	"crypto/md5"
	"encoding/hex"
	"os"
)

func FileExists(file string) (bool, error) {
	_, err := os.Stat(file)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil // file does not exist
	}
	return false, err // file may or may not exist
}

// Md5Hex returns the md5 hex string of data.
func Md5Hex(data []byte) string {
	digest := md5.New()
	digest.Write(data)
	return hex.EncodeToString(digest.Sum(nil))
}
