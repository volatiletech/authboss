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

var _confirm_email_html_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb2\x29\x2e\x29\xca\xcf\x4b\xb7\xab\xae\xd6\xab\xad\xb5\xd1\x87\xf2\x00\x01\x00\x00\xff\xff\xe7\xfa\xf4\xa7\x16\x00\x00\x00")

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

	info := bindata_file_info{name: "confirm_email.html.tpl", size: 22, mode: os.FileMode(438), modTime: time.Unix(1424982621, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _confirm_email_txt_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\xd6\xab\xad\x05\x04\x00\x00\xff\xff\x8e\x60\xe8\x72\x05\x00\x00\x00")

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

	info := bindata_file_info{name: "confirm_email.txt.tpl", size: 5, mode: os.FileMode(438), modTime: time.Unix(1424982621, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _login_html_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x7c\x92\xcb\x6a\xf3\x30\x10\x85\xf7\x81\xbc\x83\xd0\xfe\x8f\x5f\xc0\x36\xfc\xd0\x4d\xa1\x97\xd0\x86\x6e\x8b\x2c\x8f\x2b\x11\x4b\x63\x46\xe3\x5c\x10\x7e\xf7\x5a\xb5\xd3\xc4\xa5\xd4\x2b\xeb\x9c\xd1\x99\x4f\x23\xc5\xb8\x69\x5a\x15\xcc\x7b\xe8\xb5\x86\x10\x86\x61\xbd\xca\x1b\x24\x27\x94\x66\x8b\xbe\x90\x31\x3a\xec\x3d\x77\x8a\x0d\xd4\x42\xb6\xf8\x61\xbd\x1c\x06\x29\x1c\xb0\xc1\xba\x90\xdb\xe7\xd7\x9d\x2c\xd7\x2b\x31\x7e\x31\xda\x46\x6c\x80\x08\x69\x18\xc6\xec\xf9\x2f\xaf\x48\x64\x65\x8c\xe0\xeb\xd4\x20\x55\xe6\xd6\x77\x3d\x0b\x3e\x77\x50\x48\x86\x13\x4b\xa1\x47\x90\x50\xc8\xd4\xfd\x9f\x46\xcf\x84\xad\x14\x5e\x39\x48\x10\x9b\x8e\xac\x53\x74\xbe\xbf\x4b\xbd\xbb\x56\x69\x30\xd8\xd6\x40\xc9\x64\xcb\x2d\x88\x65\xc9\x41\xb5\xfd\x8f\x9d\x6f\x49\x1a\xbd\x72\xe2\x59\x80\xcc\x24\xdd\x88\x70\x44\xaa\xff\xa4\xb9\x16\x2d\x38\xb6\x17\xf9\xb7\xfc\x29\xde\xd8\xba\x06\x7f\x73\xaa\x53\xa0\xe6\x69\x5c\x2c\x89\x93\xba\xc3\x3d\xf8\x24\x67\x8b\xd9\x06\x83\xc7\x17\x70\xe0\x2a\x48\x83\xbd\x0d\xd7\x06\xf4\xbe\xc2\xd3\x25\x9e\xdc\x77\x26\x53\x0f\xb2\x14\x97\x8d\xe2\x11\x96\x97\x51\xf5\xcc\xe8\xe7\x9c\xd0\x57\xce\xb2\x2c\x1f\xd2\x55\xe7\xd9\xe4\x2d\xce\x74\x8b\xa2\xf1\xf0\x45\xa2\x84\x21\x68\x0a\x99\xd1\x24\xc9\x72\xf6\xc4\x7f\xad\xd3\x0b\xca\x33\x75\x7d\x02\x79\x96\x06\x5b\x7e\x06\x00\x00\xff\xff\x65\x0d\x58\xda\x7f\x02\x00\x00")

func login_html_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_login_html_tpl,
		"login.html.tpl",
	)
}

func login_html_tpl() (*asset, error) {
	bytes, err := login_html_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "login.html.tpl", size: 639, mode: os.FileMode(438), modTime: time.Unix(1424982621, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_html_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb4\x53\xb1\x6e\xe3\x30\x0c\xdd\xf3\x15\x84\x90\x5b\xed\xfd\x60\x6b\xc9\xdd\x70\xcb\x5d\x70\x0d\xba\x16\x8a\x45\xc7\x42\x65\xc9\xa0\xe9\x34\x81\xaa\x7f\xaf\x15\xa7\x41\xdc\x02\x09\x3a\xd4\x8b\x45\xf1\xf1\x91\xef\x81\x2a\x6a\x4f\x2d\xa8\x8a\x8d\x77\xa5\x08\xa1\xf5\x83\xe3\x4e\x71\x83\x1a\x04\x61\xe5\xf7\x48\x22\x46\x01\x2d\x72\xe3\x75\x29\xd6\xff\x1e\x36\x42\x2e\x60\xfc\x42\x78\x31\xdc\x40\x56\x5b\xd5\x37\xbf\x89\x3c\xc5\x18\x42\x16\x63\xb1\x25\xc8\x65\x08\xe8\x74\x8c\x27\x68\x61\x5c\x37\x30\xf0\xb1\xc3\x52\x30\x1e\x58\x80\x53\x2d\xa6\x8e\x59\x47\xa6\x55\x74\xfc\xf3\x2b\xb5\xe9\xac\xaa\xb0\xf1\x56\x23\xa5\x24\x1b\xb6\x08\x73\xc8\x5e\xd9\xe1\x43\xe5\x63\xba\x4a\xb9\x5c\x4e\xbd\xcf\xf3\x2d\x3b\xa3\xe1\x67\x39\x23\x78\x9f\x1a\x89\xfa\x4b\xb4\x1c\x23\x6b\x7a\x4e\x60\xe3\x34\x1e\x20\x83\x54\x9c\x00\xa4\xdc\x0e\x2f\x88\x51\x5d\xdf\x29\x27\x27\xa1\xf9\xe9\x3c\xd3\x3b\xff\xdd\x56\x5f\x79\x57\x1b\x6a\x9f\x6e\xba\xb0\x9a\x40\x70\xcf\x8d\x33\xd9\xfa\xae\x29\xd5\x27\x57\xe0\x15\xc6\xb3\xe3\x1a\x2e\x23\xfd\xe8\xc5\x57\xbc\xaa\xbe\xc7\xac\xc6\x68\x8d\xee\x6a\x59\x0e\x3d\xd5\x7f\xc7\x60\x2e\x3d\xdd\x6e\xfc\x33\xba\x49\xee\xc4\xb3\x1d\x98\xbd\x3b\x13\xf5\xc3\xb6\x35\x2c\xe4\xff\x69\xa5\x8b\x7c\xca\x5e\x3b\x53\x28\x68\x08\xeb\x52\xe4\xd6\xef\x8c\x13\x72\xa5\x5c\x85\xb6\xc8\x95\x5c\x14\x79\x7a\x27\xf2\x2d\x00\x00\xff\xff\x3b\x0a\x54\x8b\x2e\x03\x00\x00")

func recover_html_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_recover_html_tpl,
		"recover.html.tpl",
	)
}

func recover_html_tpl() (*asset, error) {
	bytes, err := recover_html_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "recover.html.tpl", size: 814, mode: os.FileMode(438), modTime: time.Unix(1424982621, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_complete_html_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb4\x52\xc1\x6e\xeb\x20\x10\xbc\xe7\x2b\x10\x7a\xe7\x70\x7f\xc2\xbe\xe4\xde\x46\x6d\xee\x15\x31\xeb\x18\x15\x16\x04\xeb\x24\x95\xe5\x7f\x2f\xc4\x49\x9c\xb6\xa9\x7a\xa8\xea\x8b\x99\x65\x67\x86\x91\x46\xb6\x3e\x3a\xa6\x1a\x32\x1e\x2b\x3e\x0c\xce\xf7\x48\x41\x51\x07\x9a\xf1\x08\x8d\xdf\x43\x14\x8d\x77\xc1\x02\x01\x1f\x47\xce\x1c\x50\xe7\x75\xc5\xd7\x8f\xcf\x1b\x5e\x2f\x58\xfe\xa4\xc1\xd0\x13\xa3\xb7\x00\x15\xef\x8c\xd6\x80\x9c\xa1\x72\x19\x91\x7f\x2d\x60\xaf\x6c\x0f\x45\x7f\x79\x1a\x14\x1d\x71\x87\x1b\x54\x4a\x07\x1f\xf5\x85\x3d\xe3\x60\x55\x03\x9d\xb7\x1a\x62\xb6\xbe\x8e\x67\xdd\xcb\xea\x24\x2d\xb7\xf1\x62\x30\x0c\x07\x43\x1d\x5b\x42\x8c\x69\x1c\xcf\xe8\x5f\x46\xd6\x24\x62\xff\x2b\x66\x50\xc3\x91\x2d\xd9\xec\x56\xd6\xa2\xc2\x1d\x5c\xf7\xc6\x51\xa6\xa0\xb0\xce\x46\xf9\x28\x4e\xe7\xc9\x63\x18\x00\x75\x21\xdc\xfe\x7e\x4e\xd6\x78\x6c\x4d\x74\x2f\xdf\x24\x5c\x4d\xd7\xec\x5e\xd2\x33\x75\xfd\xfb\xc0\x5f\x1e\xf1\x07\xc1\x3f\xd6\x21\xcb\x1c\x53\x6c\x1f\x32\x28\xef\x9e\x43\x95\xe9\xe6\x73\x35\xb6\x3d\x91\xc7\xb3\x50\xea\xb7\xce\x10\xaf\x9f\xa6\x52\x4a\x31\xdd\xde\x26\x97\x8a\x75\x11\xda\x8a\x0b\xeb\x77\x06\x79\xbd\x52\xd8\x80\x95\x42\xd5\x0b\x29\x4a\xd3\xeb\xf7\x00\x00\x00\xff\xff\xba\x89\x7e\x9e\xf0\x02\x00\x00")

func recover_complete_html_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_recover_complete_html_tpl,
		"recover_complete.html.tpl",
	)
}

func recover_complete_html_tpl() (*asset, error) {
	bytes, err := recover_complete_html_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "recover_complete.html.tpl", size: 752, mode: os.FileMode(438), modTime: time.Unix(1424982621, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_email_html_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb2\x29\x2e\x29\xca\xcf\x4b\xb7\xab\xae\xd6\xab\xad\xb5\xd1\x87\xf2\x00\x01\x00\x00\xff\xff\xe7\xfa\xf4\xa7\x16\x00\x00\x00")

func recover_email_html_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_recover_email_html_tpl,
		"recover_email.html.tpl",
	)
}

func recover_email_html_tpl() (*asset, error) {
	bytes, err := recover_email_html_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "recover_email.html.tpl", size: 22, mode: os.FileMode(438), modTime: time.Unix(1424728125, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_email_txt_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\xd6\xab\xad\x05\x04\x00\x00\xff\xff\x8e\x60\xe8\x72\x05\x00\x00\x00")

func recover_email_txt_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_recover_email_txt_tpl,
		"recover_email.txt.tpl",
	)
}

func recover_email_txt_tpl() (*asset, error) {
	bytes, err := recover_email_txt_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "recover_email.txt.tpl", size: 5, mode: os.FileMode(438), modTime: time.Unix(1424986109, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _register_html_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x94\x53\x4d\x6f\xe2\x30\x10\x3d\x93\x5f\x31\xb2\x38\x93\x3b\x72\x72\xd9\xbd\xec\x65\x85\x56\xab\x5e\x2b\x13\x4f\x88\x55\x7f\xc9\x76\x0a\x28\xca\x7f\xaf\x9d\x40\x42\x40\x6d\xe9\xc5\xf6\x8c\xde\x9b\x79\x6f\x34\xa6\xb5\x71\x0a\x58\x15\x84\xd1\x05\xe9\x3a\x65\x5a\x1d\x2c\x0b\x0d\x72\x20\x0e\x0f\xc2\x07\x74\xa4\xef\x09\x28\x0c\x8d\xe1\x05\xb1\xc6\x07\x52\x66\x2b\x2a\xd9\x1e\x25\x44\x7e\xe2\x6d\xac\x13\x8a\xb9\xf3\x9f\xdf\x11\x5b\x76\x5d\x10\x41\x22\xdc\x66\xb7\x34\x1f\x18\x89\x2a\xb4\x6d\x03\x68\xa6\xf0\x81\x0b\xe1\x6c\x63\x36\xe0\x29\x10\x78\x67\xb2\x1d\x20\x47\x11\x9a\x9b\x6a\x2f\x29\xdf\xf7\x91\x9a\x0e\xd4\x3c\x11\xad\x64\x15\x36\x46\x72\x1c\x14\x3d\x2a\x20\x90\x97\x74\xef\xe2\x99\xad\xba\x6e\x6d\x05\x87\x6d\xb1\x40\x5c\x1b\xa1\x73\x7e\x8a\xd6\x31\x92\x71\x0e\x09\x2c\x34\xc7\x13\x6c\x20\x91\x13\xc0\x31\x7d\xc0\x09\xd1\xf7\xd4\x5b\xa6\xcb\x41\x17\xcd\x87\xf7\xd8\xf0\x22\x72\x79\x2d\x67\x68\x99\xf7\x47\xe3\x38\x29\x77\x97\xd7\x67\x13\x9b\x90\x97\x59\xcd\xf1\x62\x04\xbb\x29\x7d\x6b\x7b\x69\x70\xd4\xbf\xb9\x56\x78\xd6\xc0\x52\x79\x65\x74\x2d\x9c\x7a\x9d\x1d\xfc\x1a\x33\xf0\x9d\x93\x07\xe6\xd7\x8e\xee\xcb\x3e\xe1\xec\xbe\xc3\x0f\x1c\x8e\x42\x47\x41\xbe\xdd\x2b\x31\x2f\xe4\xbf\xeb\xc7\x98\xda\x53\x06\x8d\xc3\xba\x20\x79\x74\xcf\x74\x85\x92\xe6\xac\xcc\xee\xca\x34\x82\x73\xd4\x64\xde\xfc\x93\x77\xf5\xdf\x18\xa4\xe5\x9c\x96\x7d\xc8\xfe\x37\x6f\xa8\xc7\x9d\xcd\x68\x9e\x7e\x69\xf9\x11\x00\x00\xff\xff\x0e\xa6\x2d\x81\xac\x03\x00\x00")

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

	info := bindata_file_info{name: "register.html.tpl", size: 940, mode: os.FileMode(438), modTime: time.Unix(1424982621, 0)}
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
	"login.html.tpl": login_html_tpl,
	"recover.html.tpl": recover_html_tpl,
	"recover_complete.html.tpl": recover_complete_html_tpl,
	"recover_email.html.tpl": recover_email_html_tpl,
	"recover_email.txt.tpl": recover_email_txt_tpl,
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
	"login.html.tpl": &_bintree_t{login_html_tpl, map[string]*_bintree_t{
	}},
	"recover.html.tpl": &_bintree_t{recover_html_tpl, map[string]*_bintree_t{
	}},
	"recover_complete.html.tpl": &_bintree_t{recover_complete_html_tpl, map[string]*_bintree_t{
	}},
	"recover_email.html.tpl": &_bintree_t{recover_email_html_tpl, map[string]*_bintree_t{
	}},
	"recover_email.txt.tpl": &_bintree_t{recover_email_txt_tpl, map[string]*_bintree_t{
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

