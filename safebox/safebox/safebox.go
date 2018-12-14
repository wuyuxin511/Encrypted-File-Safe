package safebox

// #cgo LDFLAGS: -ldevmapper
// #include "safebox.h"
import "C"

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"unsafe"

	KM "../keymanager"
	ut "../utils"
)

type Config struct {
	Name    string
	Dev     string
	Dir     string
	Fstype  string
	Keyfile string
}

type JsonStruct struct {
}

func Run(confName, mode string) error {
	/* parse from json */
	JsonParse := NewJsonStruct()
	confArray := []Config{}
	defaultConfigPath := ut.GetHomeDir() + "safebox_config.json"
	fmt.Println("Loading config from " + defaultConfigPath + "...")
	JsonParse.Load(defaultConfigPath, &confArray)
	if len(confArray) == 0 {
		panic("Load no config!")
	}
	conf := Config{}
	flag := false
	// Find config for specified name
	for i := range confArray {
		if confArray[i].Name == confName {
			conf = confArray[i]
			flag = true
		}
	}

	if !flag {
		panic("No name match in config file!")
	}

	name := C.CString(conf.Name)
	dev := C.CString(conf.Dev)
	dir := C.CString(conf.Dir)
	fstype := C.CString(conf.Fstype)

	var km KM.KeyManager = &KM.SafeKey{}
	km.ReadKey(conf.Keyfile)
	cipher := C.CString(km.GetCipher())
	var key []byte
	ckey := (*C.char)(unsafe.Pointer(&key))

	// Only when setup or mount target, key and password is required
	if mode == "setup" || mode == "mount" {
		key = km.GetKey()
		ckey = (*C.char)(unsafe.Pointer(&key[0]))
	}

	work := C.CString(mode)

	defer C.free(unsafe.Pointer(name))
	defer C.free(unsafe.Pointer(dev))
	defer C.free(unsafe.Pointer(dir))
	defer C.free(unsafe.Pointer(fstype))
	defer C.free(unsafe.Pointer(cipher))
	defer C.free(unsafe.Pointer(work))

	C.prepare_tgt(name, dev, dir, fstype, cipher, ckey, C.int(len(key)))
	C.do_work(work)

	return nil
}

func Setup(name string) error {
	fmt.Printf("Setup for %s...\n", name)
	return Run(name, "setup")
}

func Release(name string) error {
	fmt.Printf("Release source from %s...\n", name)
	return Run(name, "release")
}

func Mount(name string) error {
	fmt.Printf("Mount %s...\n", name)
	return Run(name, "mount")
}

func Unmount(name string) error {
	fmt.Printf("Unmount %s...\n", name)
	return Run(name, "unmount")
}

func NewJsonStruct() *JsonStruct {
	return &JsonStruct{}
}

func (jst *JsonStruct) Load(filename string, conf interface{}) {
	data, err := ioutil.ReadFile(filename)
	ut.PanicIfFail(err, "Reading config failed!")

	err = json.Unmarshal(data, conf)
	ut.PanicIfFail(err, "Parsing config failed!")
}
