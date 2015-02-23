package render

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"os"
	"time"
	"io/ioutil"
	"path"
	"path/filepath"
)

func bindata_read(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindata_file_info struct {
	name string
	size int64
	mode os.FileMode
	modTime time.Time
}

func (fi bindata_file_info) Name() string {
	return fi.name
}
func (fi bindata_file_info) Size() int64 {
	return fi.size
}
func (fi bindata_file_info) Mode() os.FileMode {
	return fi.mode
}
func (fi bindata_file_info) ModTime() time.Time {
	return fi.modTime
}
func (fi bindata_file_info) IsDir() bool {
	return false
}
func (fi bindata_file_info) Sys() interface{} {
	return nil
}

var _confirm_email_html_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb2\x29\x2e\x29\xca\xcf\x4b\xb7\xab\xae\xd6\xf3\xc9\xcc\xcb\xae\xad\xb5\xd1\x87\x8a\x00\x02\x00\x00\xff\xff\xe1\x46\x1b\xff\x1a\x00\x00\x00")

func confirm_email_html_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_confirm_email_html_tpl,
		"confirm_email.html.tpl",
	)
}

func confirm_email_html_tpl() (*asset, error) {
	bytes, err := confirm_email_html_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "confirm_email.html.tpl", size: 26, mode: os.FileMode(438), modTime: time.Unix(1424471280, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _confirm_email_txt_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\xd6\xf3\xc9\xcc\xcb\xae\xad\x05\x04\x00\x00\xff\xff\x41\xf7\xa1\x3d\x09\x00\x00\x00")

func confirm_email_txt_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_confirm_email_txt_tpl,
		"confirm_email.txt.tpl",
	)
}

func confirm_email_txt_tpl() (*asset, error) {
	bytes, err := confirm_email_txt_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "confirm_email.txt.tpl", size: 9, mode: os.FileMode(438), modTime: time.Unix(1424471280, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _login_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x7c\x92\x4d\x6b\xf3\x30\x0c\x80\xef\x85\xfe\x07\xe3\xfb\xdb\xfc\x81\x24\xf0\xc2\x2e\x83\x7d\x94\xad\xf7\xe1\x38\xca\x62\x1a\x5b\x41\x96\xfb\x41\xc8\x7f\x9f\xbd\xa4\x6b\x02\x63\x39\x05\x49\x7e\xf4\x58\xf2\x30\xec\x9a\x4e\xf9\xf6\xc3\x07\xad\xc1\xfb\x71\xdc\x6e\xf2\x06\xc9\x0a\xa5\xd9\xa0\x2b\x64\xd6\xe1\xa7\x71\x52\x58\xe0\x16\xeb\x42\xee\x5f\xdf\x0f\xb2\xdc\x6e\x44\xfc\x86\xc1\x34\x62\x07\x44\x48\xe3\x18\x51\xf3\x5f\x5e\x91\xc8\xca\x61\x00\x57\x27\x5e\xaa\xcc\x8d\xeb\x03\x0b\xbe\xf6\x50\x48\x86\x0b\x4b\xa1\x63\x5f\x5f\xc8\xd4\xec\x9f\x46\xc7\x84\x9d\x14\x4e\xd9\x58\x10\x51\x3d\x19\xab\xe8\xfa\xf8\x30\x8e\x52\xf4\x9d\xd2\xd0\x62\x57\x03\xa5\x24\x1b\xee\x40\xac\x4b\x4e\xaa\x0b\xd3\xc9\xe0\x81\x12\x26\x46\xcb\xc9\x64\xa5\x30\x3b\xf4\xb1\xf9\x19\xa9\xfe\xd3\xe3\x5e\xb4\x32\xd8\xdf\xc2\xbf\xf1\x27\x7c\x6b\xea\x1a\xdc\xe2\x3e\x17\x4f\xcd\xcb\x64\xb5\x70\x4d\xd1\x03\x1e\xc1\xa5\x70\xb6\x9a\xaa\x6f\xf1\xfc\x06\x16\x6c\x05\x69\xa4\x4b\xb8\x6e\x41\x1f\x2b\xbc\xdc\xf0\x64\x7f\x98\x4c\x01\x64\x29\x6e\x07\xc5\x33\xac\xd7\x50\x05\x66\x74\x33\xc7\x87\xca\x1a\x96\xe5\x53\xda\x70\x9e\x4d\xb9\xd5\x9d\x96\x2a\x1a\x4f\xdf\x26\x4a\xb4\x04\x4d\x7c\x18\x34\x85\x64\x39\xe7\xc4\x7f\xad\x31\x38\xce\x33\x75\x5f\x7e\x9e\xa5\xc1\x96\x5f\x01\x00\x00\xff\xff\xe7\xed\x2e\xa4\x68\x02\x00\x00")

func login_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_login_tpl,
		"login.tpl",
	)
}

func login_tpl() (*asset, error) {
	bytes, err := login_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "login.tpl", size: 616, mode: os.FileMode(438), modTime: time.Unix(1424735294, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_complete_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb4\x52\xc1\x6e\xea\x30\x10\xbc\xf3\x15\x2b\xeb\x9d\xf1\xfd\xc9\xc9\x85\x7b\x8b\x5a\xee\x95\x89\x37\xc4\xaa\xb3\x8e\xd6\x0e\x50\x45\xf9\xf7\xda\x04\x08\x6d\xa9\x7a\xa8\x9a\x4b\x3c\xeb\x9d\x19\x8f\x34\xaa\xf6\xdc\x82\xae\xa2\xf5\x54\x08\xc9\x58\xf9\x3d\xb2\xac\x7c\xdb\x39\x8c\x28\xa0\xc5\xd8\x78\x53\x88\xf5\xe3\xf3\x46\x94\x0b\x48\x9f\xb2\xd4\xf5\x11\xe2\x5b\x87\x85\x68\xac\x31\x48\x02\x48\xb7\x09\x45\xff\x9a\xc1\x5e\xbb\x3e\xa1\x61\x58\x9e\x06\xe3\x28\x40\xde\xe1\x76\x3a\x84\x83\x67\x73\x61\xcf\xb8\x73\xba\xc2\xc6\x3b\x83\x9c\xac\xaf\xe3\x59\xf7\xb2\x3a\x49\xab\x2d\x5f\x0c\x86\xe1\x60\x63\x03\x4b\x64\x0e\xe3\x78\x46\xff\x12\x72\x36\x44\xf8\x5f\x80\x25\x83\x47\x58\xc2\xec\x96\xd7\x58\xd3\x0e\xaf\x7b\xe3\xa8\x42\xa7\xa9\x4c\x46\xe9\x28\x4f\xe7\xc9\x63\x18\x90\x4c\x26\xdc\xfe\x7e\x4e\x56\x79\xaa\x2d\xb7\x2f\xdf\x24\x5c\x4d\xd7\x70\x2f\xe9\x99\xba\xfe\x7d\xe0\x2f\x8f\xf8\x83\xe0\x1f\xeb\x90\x64\x8e\x81\xeb\x87\x04\xf2\xbb\xe7\x50\x79\xba\xf9\x5c\x8d\x6d\x1f\xa3\xa7\xb3\x50\xe8\xb7\xad\x8d\xa2\x7c\x9a\x1a\xa9\xe4\x74\x7b\x9b\x5c\x69\x68\x18\xeb\x54\x5b\xe7\x77\x96\x44\xb9\xd2\x54\xa1\x53\x52\x97\x0b\x25\x73\xb1\xcb\xf7\x00\x00\x00\xff\xff\x67\x02\x74\x02\xdf\x02\x00\x00")

func recover_complete_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_recover_complete_tpl,
		"recover-complete.tpl",
	)
}

func recover_complete_tpl() (*asset, error) {
	bytes, err := recover_complete_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "recover-complete.tpl", size: 735, mode: os.FileMode(438), modTime: time.Unix(1424735204, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_html_email = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb2\x29\x2e\x29\xca\xcf\x4b\xb7\xab\xae\xd6\xab\xad\xb5\xd1\x87\xf2\x00\x01\x00\x00\xff\xff\xe7\xfa\xf4\xa7\x16\x00\x00\x00")

func recover_html_email_bytes() ([]byte, error) {
	return bindata_read(
		_recover_html_email,
		"recover-html.email",
	)
}

func recover_html_email() (*asset, error) {
	bytes, err := recover_html_email_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "recover-html.email", size: 22, mode: os.FileMode(438), modTime: time.Unix(1424728125, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_text_email = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\xd6\xab\xad\x05\x04\x00\x00\xff\xff\x8e\x60\xe8\x72\x05\x00\x00\x00")

func recover_text_email_bytes() ([]byte, error) {
	return bindata_read(
		_recover_text_email,
		"recover-text.email",
	)
}

func recover_text_email() (*asset, error) {
	bytes, err := recover_text_email_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "recover-text.email", size: 5, mode: os.FileMode(438), modTime: time.Unix(1424728129, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb4\x53\x4d\x6f\xe2\x30\x10\xbd\xf3\x2b\x46\x16\x7b\x25\xf7\x55\xe2\x0b\xbb\x87\x5e\x5a\xd4\xa2\x5e\x2b\x93\x4c\x88\x55\xc7\x8e\x26\x13\x0a\x4a\xfd\xdf\x6b\x63\x8a\x48\x2b\x81\x7a\x68\x2e\x99\x8f\x37\x2f\xf3\x9e\x26\x79\xed\xa8\x05\x55\xb2\x76\xb6\x10\x19\x61\xe9\x76\x48\x02\x5a\xe4\xc6\x55\x85\x58\x3d\x3c\xad\x85\x9c\x41\x78\xc6\xf1\x4d\x73\x03\x8b\xda\xa8\xbe\xf9\x4f\xe4\xc8\xfb\x71\x5c\x78\x9f\x6f\x08\x32\x39\x8e\x68\x2b\xef\x8f\xd0\x5c\xdb\x6e\x60\xe0\x43\x87\x85\x60\xdc\xb3\x00\xab\xda\x10\x07\x7c\x47\xba\x55\x74\xb8\xfb\xe7\xbd\x80\xce\xa8\x12\x1b\x67\x2a\xa4\xd8\x64\xcd\x06\x61\x0a\xd9\x29\x33\x7c\x99\x7c\x8e\xa5\xd8\xcb\x64\xfa\xf6\x69\xbf\x79\xa7\x2b\xf8\x5b\x4c\x08\x3e\xb7\x46\xa2\xfe\x9c\xcd\x43\x66\x74\xcf\x11\xac\x6d\x85\x7b\x58\x40\x1c\x8e\x00\x52\x76\x8b\x67\x44\x50\xd7\x77\xca\xca\x24\x34\x3b\xc6\x13\xbd\xd3\xd7\x75\xf5\xa5\xb3\xb5\xa6\xf6\xe5\xaa\x0b\xcb\x04\x82\x5b\x6e\x9c\xc8\x56\x37\x4d\x29\xbf\xb9\x02\xef\x10\x62\xcb\x35\x9c\x57\xfa\xd3\x8b\x9f\x78\x55\xfe\x8e\x59\x8d\xae\x2a\xb4\x17\xc7\xb2\xef\xa9\xbe\x0f\xc9\x54\x7a\xac\xae\xdd\x2b\xda\x24\x37\xf1\x6c\x06\x66\x67\x4f\x44\xfd\xb0\x69\x35\x0b\xf9\x98\xee\x39\xcf\x52\xf7\xd2\x99\x5c\x41\x43\x58\x87\xa3\x37\x6e\xab\xad\x90\x4b\x65\x4b\x34\x79\xa6\xe4\x2c\xcf\xe2\x6f\x21\x3f\x02\x00\x00\xff\xff\x93\x4d\xba\xa6\x1d\x03\x00\x00")

func recover_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_recover_tpl,
		"recover.tpl",
	)
}

func recover_tpl() (*asset, error) {
	bytes, err := recover_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "recover.tpl", size: 797, mode: os.FileMode(438), modTime: time.Unix(1424735212, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _register_html_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x94\x93\x31\x6f\xf3\x20\x10\x86\xe7\xf8\x57\x9c\x50\xe6\x78\x8f\x30\xcb\xf7\x2d\x95\xaa\x2a\x43\xd5\xb5\x22\xe6\x1c\xa3\x62\x40\x40\x9a\x44\x96\xff\x7b\xc1\x4e\xec\x38\x51\xdb\x74\xc1\xdc\xe9\x3d\xee\x7d\x4e\x67\x5a\x19\xd7\x00\x2f\x83\x34\xba\x20\x0e\x77\xd2\x07\x74\x04\x1a\x0c\xb5\x11\x05\xb1\xc6\x07\xc2\xb2\x05\x55\x7c\x8b\x0a\xa2\xba\x20\x6d\xbb\xb2\x4e\x36\xdc\x9d\x9e\xfe\x77\x1d\x61\xf3\x78\x4d\xf3\x5e\x9b\x8a\xa4\xb6\xfb\x00\x9a\x37\x78\x57\x05\xe1\x64\x63\x36\xe0\x31\x10\xf8\xe4\x6a\xdf\x4b\x0e\x32\xd4\x30\xe9\xde\x52\xbe\xeb\x62\x69\x3a\x50\x8b\x54\x68\x15\x2f\xb1\x36\x4a\xe0\xbd\x17\xc8\x19\xdd\xba\x78\x66\x8b\xb6\x5d\x5a\x29\x60\x5d\xc0\xb5\xe2\xd2\x02\x9d\xf3\x63\xb4\x8c\x91\x8a\xe0\x49\x2c\xb5\xc0\x23\xac\x20\x15\x27\x81\xe3\x7a\x87\xa3\xa2\xeb\xa8\xb7\x5c\xb3\xde\x11\xcd\xfb\xfb\xd0\xf0\x6c\x6f\xfe\x99\xcf\xcd\x72\xef\x0f\xc6\x09\xc2\x36\xe7\xdb\x77\xb3\x1a\x95\xe7\x29\x4d\xf1\x0c\x7e\x33\xa6\xaf\xb1\xe7\x80\x83\xff\xd5\xe5\x85\x47\x01\xe6\xce\x4b\xa3\x2b\xe9\x9a\xf7\x89\xe0\xdf\x90\x81\xdf\x48\xee\x2a\x7f\x26\xba\x7d\xf6\x01\xb2\xdb\x0e\x7f\x20\x1c\x8c\x0e\x86\xfc\x7e\xdb\xc8\x69\x15\x9f\xcd\x4e\x6a\x32\xf6\xa6\x1c\x6a\x87\x55\x41\xf2\x88\xce\x75\x89\x8a\xe6\x9c\x65\x37\x6f\xd4\x52\x08\xd4\x64\x5a\xf8\xa3\x77\xd5\x4b\x0c\xd2\x66\x8e\x3b\xde\x67\x5f\xcd\x07\xea\x61\x61\x33\x9a\xa7\x9f\x90\x7d\x05\x00\x00\xff\xff\xe5\x8f\x49\x7c\x8b\x03\x00\x00")

func register_html_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_register_html_tpl,
		"register.html.tpl",
	)
}

func register_html_tpl() (*asset, error) {
	bytes, err := register_html_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "register.html.tpl", size: 907, mode: os.FileMode(438), modTime: time.Unix(1424722297, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"confirm_email.html.tpl": confirm_email_html_tpl,
	"confirm_email.txt.tpl": confirm_email_txt_tpl,
	"login.tpl": login_tpl,
	"recover-complete.tpl": recover_complete_tpl,
	"recover-html.email": recover_html_email,
	"recover-text.email": recover_text_email,
	"recover.tpl": recover_tpl,
	"register.html.tpl": register_html_tpl,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for name := range node.Children {
		rv = append(rv, name)
	}
	return rv, nil
}

type _bintree_t struct {
	Func func() (*asset, error)
	Children map[string]*_bintree_t
}
var _bintree = &_bintree_t{nil, map[string]*_bintree_t{
	"confirm_email.html.tpl": &_bintree_t{confirm_email_html_tpl, map[string]*_bintree_t{
	}},
	"confirm_email.txt.tpl": &_bintree_t{confirm_email_txt_tpl, map[string]*_bintree_t{
	}},
	"login.tpl": &_bintree_t{login_tpl, map[string]*_bintree_t{
	}},
	"recover-complete.tpl": &_bintree_t{recover_complete_tpl, map[string]*_bintree_t{
	}},
	"recover-html.email": &_bintree_t{recover_html_email, map[string]*_bintree_t{
	}},
	"recover-text.email": &_bintree_t{recover_text_email, map[string]*_bintree_t{
	}},
	"recover.tpl": &_bintree_t{recover_tpl, map[string]*_bintree_t{
	}},
	"register.html.tpl": &_bintree_t{register_html_tpl, map[string]*_bintree_t{
	}},
}}

// Restore an asset under the given directory
func RestoreAsset(dir, name string) error {
        data, err := Asset(name)
        if err != nil {
                return err
        }
        info, err := AssetInfo(name)
        if err != nil {
                return err
        }
        err = os.MkdirAll(_filePath(dir, path.Dir(name)), os.FileMode(0755))
        if err != nil {
                return err
        }
        err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
        if err != nil {
                return err
        }
        err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
        if err != nil {
                return err
        }
        return nil
}

// Restore assets under the given directory recursively
func RestoreAssets(dir, name string) error {
        children, err := AssetDir(name)
        if err != nil { // File
                return RestoreAsset(dir, name)
        } else { // Dir
                for _, child := range children {
                        err = RestoreAssets(dir, path.Join(name, child))
                        if err != nil {
                                return err
                        }
                }
        }
        return nil
}

func _filePath(dir, name string) string {
        cannonicalName := strings.Replace(name, "\\", "/", -1)
        return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

