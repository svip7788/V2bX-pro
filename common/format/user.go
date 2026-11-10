package format

import "unique"

// UserTag 返回驻留后的 "tag|uuid"，limiter、xray 各自保存的同一用户共享一份字符串内存
func UserTag(tag string, uuid string) string {
	return unique.Make(tag + "|" + uuid).Value()
}
