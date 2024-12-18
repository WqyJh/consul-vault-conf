package zero

import (
	"fmt"
	"log"
	"path"
	"strings"

	confz "github.com/WqyJh/consul-vault-conf"
	"github.com/asim/go-micro/v3/util/file"
	"github.com/zeromicro/go-zero/core/conf"
)

var (
	loaders = map[string]func([]byte, any) error{
		".json": conf.LoadFromJsonBytes,
		".toml": conf.LoadFromTomlBytes,
		".yaml": conf.LoadFromYamlBytes,
		".yml":  conf.LoadFromYamlBytes,
	}
)

func Load[T any](f string, opts ...conf.Option) (T, error) {
	var v T
	exists, err := file.Exists(f)
	if err != nil {
		return v, err
	}
	if exists {
		err := conf.Load(f, &v, opts...)
		if err == nil {
			return v, nil
		}
	}
	content, err := confz.ConsulGet(f)
	if err != nil {
		return v, err
	}

	loader, ok := loaders[strings.ToLower(path.Ext(f))]
	if !ok {
		return v, fmt.Errorf("unrecognized file type: %s", f)
	}

	err = loader(content, &v)
	if err != nil {
		return v, err
	}
	return v, nil
}

func MustLoad[T any](f string, opts ...conf.Option) T {
	v, err := Load[T](f, opts...)
	if err != nil {
		log.Fatalf("error: config file %s, %s", f, err.Error())
	}
	return v
}

func SecurityLoad[T any](f string, opts ...conf.Option) (T, error) {
	v, err := Load[T](f, opts...)
	if err != nil {
		return v, err
	}

	err = confz.DecryptInplace(&v)
	if err != nil {
		return v, err
	}

	return v, nil
}

func SecurityMustLoad[T any](f string, opts ...conf.Option) T {
	v, err := SecurityLoad[T](f, opts...)
	if err != nil {
		log.Fatalf("error: config file %s, %+v", f, err)
	}
	return v
}
