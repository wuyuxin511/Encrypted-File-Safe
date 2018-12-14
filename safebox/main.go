package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	KM "./keymanager"
	"./safebox"
	ut "./utils"

	flags "github.com/jessevdk/go-flags"
)

func main() {

	/* read in work mode from cmd

	genkey:		Generate new key.
	setup:      Setup device-mapper rules.
	release:    Release device-mapper.
				Now the encrypted filesystem is ready for use.
	mount:      Mount filesystem on required directory.
	unmount:     Unmount filesystem.
	*/
	args := os.Args
	// Only allow 1 avaliable argument
	if args == nil || len(args) < 2 || len(args) > 3 || string(args[1][0]) != "-" {
		panic("Invalid command. Use -h or --help.")
	}
	var opts struct {
		GenKey    []bool `required:"false" short:"g" long:"generate-key" description:"Generate a new key for encrypted filesystem. Size can be specified."`
		ChangePwd string `required:"false" short:"c" long:"change-pwd" description:"Change password for a generated key."`
		Setup     string `required:"false" short:"s" long:"setup" description:"Setup the device-mapper and loopback devices. "`
		Release   string `required:"false" short:"r" long:"release" description:"Releases all device-mapper and loopback devices related."`
		Mount     string `required:"false" short:"m" long:"mount" description:"Mount the specified filesystem."`
		Unmount   string `required:"false" short:"u" long:"unmount" description:"Unmount the specified filesystem."`
	}
	flags.Parse(&opts)

	switch {
	case len(opts.GenKey) > 0:
		genKey()
	case len(opts.ChangePwd) > 0:
		changePwd(opts.ChangePwd)
	case len(opts.Setup) > 0:
		safebox.Setup(opts.Setup)
	case len(opts.Release) > 0:
		safebox.Release(opts.Release)
	case len(opts.Mount) > 0:
		safebox.Mount(opts.Mount)
	case len(opts.Unmount) > 0:
		safebox.Unmount(opts.Unmount)
	default:
		fmt.Println("Nothing done. Please refer to -h or --help.")
	}
}

func genKey() {
	path := ut.ReadUserInputWithDefault("Enter the filepath to store your key", ut.GetHomeDir()+"safebox_key_"+fmt.Sprintf("%d", time.Now().Unix()))
	cipher := ut.ReadUserInputWithDefault("Enter the cipher you want to use", "twofish")
	lengthS := ut.ReadUserInputWithDefault("Enter the key size to generate", "32")
	length, err := strconv.Atoi(lengthS)
	ut.PanicIfFail(err, "Invalid input!")
	comment := ut.ReadUserInputWithDefault("Enter your comment info", "")
	var key = KM.SafeKey{}
	var km KM.KeyManager = &key
	var kim KM.KeyinfoManager = &key
	km.KeyGen(cipher, length)
	kim.SetComment(comment)
	km.SaveKey(path)
}

func changePwd(path string) {
	var key = KM.SafeKey{}
	var km KM.KeyManager = &key
	km.ChangePassword(path)
	fmt.Println("Successfully changed!")
}
