package user

import "fmt"

type User interface {
	addBlockDevice() int
	mountDevice() int
	getBlockDeviceInfo() int
	setPasswd() int
}
