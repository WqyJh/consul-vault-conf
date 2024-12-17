package confz

import (
	"context"
	"reflect"
	"strings"
)

type VaultConf struct {
	Addr  string `json:"addr,env=VAULT_ADDR"`
	Token string `json:"token,env=VAULT_TOKEN"`
}

type vaultDecoder struct {
	ctx           context.Context
	err           error
	secretFetcher SecretFetcher
	encDecoder    SecretFetcher
}

// Decode decrypts the encrypted string fields start with `ENC~` in fields tree of obj and returns the decrypted obj.
func Decode(obj interface{}, secretFetcher SecretFetcher, encDecoder SecretFetcher) (interface{}, error) {
	d := vaultDecoder{
		ctx:           context.Background(),
		secretFetcher: secretFetcher,
		encDecoder:    encDecoder,
	}
	return d.decode(obj)
}

func (d *vaultDecoder) decode(obj interface{}) (interface{}, error) {
	// Wrap the src in a reflect.Value
	src := reflect.ValueOf(obj)

	dst := reflect.New(src.Type()).Elem()
	d.recursive(dst, src)
	if d.err != nil {
		return nil, d.err
	}

	// Remove the reflection wrapper
	return dst.Interface(), nil
}

func (d *vaultDecoder) Error() error {
	return d.err
}

func (d *vaultDecoder) recursive(dst, src reflect.Value) {
	if d.err != nil {
		return
	}

	switch src.Kind() {
	// The first cases handle nested structures and translate them recursively

	// If it is a pointer we need to unwrap and call once again
	case reflect.Ptr:
		// To get the actual value of the original we have to call Elem()
		// At the same time this unwraps the pointer so we don't end up in
		// an infinite recursion
		originalValue := src.Elem()
		// Check if the pointer is nil
		if !originalValue.IsValid() {
			return
		}
		// Allocate a new object and set the pointer to it
		dst.Set(reflect.New(originalValue.Type()))
		// Unwrap the newly created pointer
		d.recursive(dst.Elem(), originalValue)

	// If it is an interface (which is very similar to a pointer), do basically the
	// same as for the pointer. Though a pointer is not the same as an interface so
	// note that we have to call Elem() after creating a new object because otherwise
	// we would end up with an actual pointer
	case reflect.Interface:
		// Get rid of the wrapping interface
		originalValue := src.Elem()
		// Create a new object. Now new gives us a pointer, but we want the value it
		// points to, so we have to call Elem() to unwrap it
		copyValue := reflect.New(originalValue.Type()).Elem()
		d.recursive(copyValue, originalValue)
		dst.Set(copyValue)

	// If it is a struct we translate each field
	case reflect.Struct:
		for i := 0; i < src.NumField(); i += 1 {
			d.recursive(dst.Field(i), src.Field(i))
		}

	// If it is a slice we create a new slice and translate each element
	case reflect.Slice:
		dst.Set(reflect.MakeSlice(src.Type(), src.Len(), src.Cap()))
		for i := 0; i < src.Len(); i += 1 {
			d.recursive(dst.Index(i), src.Index(i))
		}

	// If it is a map we create a new map and translate each value
	case reflect.Map:
		dst.Set(reflect.MakeMap(src.Type()))
		for _, key := range src.MapKeys() {
			originalValue := src.MapIndex(key)
			// New gives us a pointer, but again we want the value
			copyValue := reflect.New(originalValue.Type()).Elem()

			d.recursive(copyValue, originalValue)
			dst.SetMapIndex(key, copyValue)
		}

	// Otherwise we cannot traverse anywhere so this finishes the the recursion

	// If it is a string translate it (yay finally we're doing what we came for)
	case reflect.String:
		str := src.String()
		if strings.HasPrefix(str, "SEC~") {
			value, err := d.secretFetcher.Fetch(d.ctx, str[4:])
			if err != nil {
				d.err = err
				return
			}
			dst.SetString(value)
		} else if strings.HasPrefix(str, "ENC~") {
			value, err := d.encDecoder.Fetch(d.ctx, str[4:])
			if err != nil {
				d.err = err
				return
			}
			dst.SetString(value)
		} else {
			dst.SetString(str)
		}

	// And everything else will simply be taken from the original
	default:
		dst.Set(src)
	}
}
