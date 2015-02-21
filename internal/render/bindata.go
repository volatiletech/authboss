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

var _login_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x7c\x52\x5b\x6e\x83\x30\x10\xfc\xaf\xd4\x3b\xac\xf6\xbf\xe5\x02\x80\xd4\xff\x3e\xa2\x36\x3d\x80\x31\x4b\x41\xc1\x5e\xb4\xd8\x49\x2a\xc4\xdd\x6b\x07\x9c\x87\x14\x95\xaf\xd5\xec\x30\x33\xcc\x92\x37\x2c\x06\x94\x76\x1d\xdb\x02\xb3\x9e\x7f\x3a\x8b\x60\xc8\xb5\x5c\x17\xb8\xf9\xf8\xda\x62\xf9\xf8\x00\xe1\x99\xa6\xae\x81\x67\x12\x61\x99\xe7\x69\x4a\x53\x5e\x09\x64\xe5\x34\x91\xad\xe7\x79\x61\xe6\x9d\x1d\xbc\x03\xf7\x3b\x50\x81\x8e\x8e\x0e\x41\xf7\x6a\x1c\x0b\x8c\x66\x4f\x9a\xad\x13\xee\x11\xac\x32\x81\xe0\x47\x92\x38\x21\x0c\xbd\xd2\xd4\x72\x5f\x93\x14\xf8\x7d\x86\xf7\xaa\xf7\x81\x17\x2c\x13\x75\x9e\x53\xa8\xd5\x6a\xf5\x1a\x82\xc9\x81\xa5\xfe\xd7\xef\x42\xba\xf1\xdb\x24\xb8\xbc\xf3\x11\x6d\x57\xd7\x64\x93\x42\x48\x72\x1c\xa5\x79\x5f\x92\x5c\xe5\x8b\xe8\x96\x77\x64\x23\x9c\xdd\xf4\x36\xb6\x7c\xf8\x24\x43\xa6\xa2\x58\xda\xb5\xb8\x6e\x49\xef\x2a\x3e\x26\x79\x31\x67\x4d\x27\x9e\xb0\x84\xf4\x22\xbc\xd1\x6d\xd1\xa7\xee\xd3\xec\x9d\x63\xbb\x6a\x8e\xbe\x32\x9d\xc3\xf2\x35\xde\x33\xcf\x96\xdd\x9d\x40\x9a\xf7\xa7\x3c\x0a\x5a\xa1\x26\xfc\x00\xb2\x40\x58\xae\x3b\x78\xd1\x9a\xbd\x75\x79\xa6\x2e\x47\xce\xb3\x58\x6c\xf9\x17\x00\x00\xff\xff\x1e\x0e\xca\x3a\x3c\x02\x00\x00")

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

	info := bindata_file_info{name: "login.tpl", size: 572, mode: os.FileMode(438), modTime: time.Unix(1424503580, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_complete_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xd4\x54\xc1\x8e\xd3\x30\x10\xbd\xef\x57\x8c\xac\xbd\xa6\xb9\xa3\xa4\x17\x04\x37\x60\x45\xf7\xc0\xd5\x8d\xa7\x1b\x6b\x1d\xdb\x4c\x9c\xc2\xca\xf2\xbf\x33\x8e\x9b\x6e\x89\x5a\x81\x84\x38\x6c\x24\x2b\x9e\xb1\xe7\x79\xde\x7b\xd2\x34\x07\x47\x03\xc8\x2e\x68\x67\x5b\x51\x13\x76\xee\x88\x54\x77\x6e\xf0\x06\x03\x0a\x18\x30\xf4\x4e\xb5\xe2\xe1\xcb\xee\x51\x6c\xef\x80\xbf\x46\x5b\x3f\x05\x08\x2f\x1e\x5b\xd1\x6b\xa5\xd0\x0a\xb0\x72\xe0\x28\xb8\xe7\x1c\x1c\xa5\x99\x38\x8a\x71\xf3\x98\x13\x29\x09\xa8\x4b\x6d\x8c\xf7\x5e\x8e\xe3\x0f\x47\xea\x03\xd1\x08\xef\x5a\xd8\xf0\xe6\x93\xf4\x9b\x25\x9f\x52\x79\x45\xe9\x23\x74\x86\x93\xad\xc8\x4d\x56\x4f\xe4\x26\x1f\xa3\x3e\xc0\x6f\x10\x29\x41\x2f\xc7\x0a\x89\x1c\xc5\x88\x96\xeb\x4f\x7d\xae\x51\xe6\xb6\x0b\xcc\xc5\x8d\xf9\xd6\xe8\xa5\xbd\x72\xad\x92\x4a\x39\x2b\xb6\x8d\x3e\x77\x22\xe1\x20\x2b\xe3\xba\x67\xce\xd6\x9a\x57\x2e\x5d\xa1\x15\x7d\x2e\x7b\xef\x9c\x0d\xe4\x8c\x38\x89\x16\xf0\x67\x58\x24\x5b\xb8\x08\xf0\x46\x76\xd8\x3b\xa3\x90\x58\xef\x73\x9a\xf0\xfb\xa4\x09\xd5\x22\xe1\xfc\x44\xcd\xbc\x5e\xc3\x18\x49\xda\x27\x84\x7b\x56\x21\x4b\xba\x12\xe8\x36\xd7\x1e\x8d\xaf\xf6\x85\x4e\x8c\x9e\xb4\x0d\x33\x48\x4a\x6b\x62\x27\x69\xef\x2e\x5e\x5f\x0c\x65\x72\x07\x4d\xc3\xc3\x0d\x5f\x57\xc7\x7f\x61\xef\x15\xc0\xb7\xee\xf2\x8a\xd2\xca\xec\xf7\xe5\x14\xfe\xcd\xf4\xab\xb2\xfd\x27\xef\xe7\xed\x7e\x0a\xc1\x9d\xf1\xf6\xc1\x02\xaf\x8a\x91\x06\x49\x2f\xf3\xbe\xc0\x9f\xf4\x18\xa7\xfd\xa0\x83\xd8\xee\xe6\x7f\x53\x97\xf2\x3f\xce\x14\x9e\x22\xdf\x76\x5f\x3f\x7e\xe6\x20\x0f\x92\xd7\xd9\x92\xb3\x97\xf3\xa5\xa9\xb3\x0b\xdb\x5f\x01\x00\x00\xff\xff\x30\xbb\xc0\xa5\xd3\x04\x00\x00")

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

	info := bindata_file_info{name: "recover-complete.tpl", size: 1235, mode: os.FileMode(438), modTime: time.Unix(1424471280, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_html_email = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb2\x29\x2e\x29\xca\xcf\x4b\xb7\xab\xae\xd6\xf3\xc9\xcc\xcb\xae\xad\xb5\xd1\x87\x8a\x00\x02\x00\x00\xff\xff\xe1\x46\x1b\xff\x1a\x00\x00\x00")

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

	info := bindata_file_info{name: "recover-html.email", size: 26, mode: os.FileMode(438), modTime: time.Unix(1424471280, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_text_email = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\xd6\xf3\xc9\xcc\xcb\xae\xad\x05\x04\x00\x00\xff\xff\x41\xf7\xa1\x3d\x09\x00\x00\x00")

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

	info := bindata_file_info{name: "recover-text.email", size: 9, mode: os.FileMode(438), modTime: time.Unix(1424471280, 0)}
	a := &asset{bytes: bytes, info:  info}
	return a, nil
}

var _recover_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xd4\x94\x4f\x8f\x9b\x30\x10\xc5\xef\xfb\x29\x46\xd6\x5e\x09\xf7\x0a\xb8\x44\xed\xad\x7f\xb4\xbb\x91\x7a\x9d\xc0\x10\xac\x18\x1b\x0d\x26\xea\xca\xe2\xbb\xd7\xc6\x24\x9b\x58\x89\xd4\x1e\x7a\x28\x12\x92\x19\xc6\xbf\xe1\xbd\x67\x51\xb4\x86\x7b\xc0\xda\x4a\xa3\x4b\x91\x33\xd5\xe6\x44\x2c\xa0\x27\xdb\x99\xa6\x14\x3f\xbe\xbf\xbe\x89\xea\x09\xfc\xe5\xdc\xf3\x34\x12\x6b\xec\xe9\x33\xf3\x08\x9f\x4a\xd8\xf8\xc5\x57\x1c\x36\xe7\xfa\x3c\x2f\x9d\x45\x23\x4f\x50\x2b\x1c\xc7\x52\x04\x7e\x76\x60\x33\x0d\xce\xc9\x16\x6e\x10\xf3\x0c\x1d\x8e\x19\x31\x1b\x76\x8e\x74\x33\xcf\xeb\xac\x94\x22\xf5\x30\xd9\x88\xb9\xea\x58\xba\xc6\x01\xf5\x9d\xb6\x0c\x9b\xc6\x68\x51\x15\xf2\xf2\x25\x08\x2d\x66\x61\xbe\xaf\xe6\xd2\xdf\x61\x6b\x42\x5b\x08\x37\xdf\x5e\x1b\x6d\xd9\x28\x01\xf6\x7d\xa0\x52\x58\xfa\x65\x05\x04\x05\xa5\x38\x6b\x11\x30\x28\xac\xa9\x33\xaa\x21\x2e\xc5\xee\x52\x3e\xa1\x9a\x7c\x9f\x73\x9b\xdd\xc5\x21\x01\xf9\x95\xc6\xdc\x8b\xfc\x78\x74\x8e\x51\x1f\x08\x9e\xbd\x25\xc1\xdf\xc4\xad\xc7\xc2\x3b\x52\x43\xb6\x57\xa6\x3e\x8a\xca\xb9\x81\xa5\xb6\x0b\x64\x9e\x53\x95\xab\xcf\x4f\x57\xd3\xcf\xe9\x7a\xa5\xad\xe4\x7e\xf7\x20\xe4\xe4\xf5\x1f\x64\x7d\x07\xf8\xbf\x47\x9e\x48\x4a\x92\xdf\xc6\xb7\x70\xef\x04\x6c\x53\xfb\xfe\xea\x20\xdc\xb5\xf2\x1f\x9d\x87\xb0\x8c\xcf\xfb\xc9\x5a\x73\x81\xee\xad\x06\x7f\x67\x1e\xd7\x23\xbf\x2f\xeb\x38\x63\x35\x6a\x9c\xf6\xbd\xb4\xa2\x7a\x89\x7f\x91\x22\x8f\xfb\x23\xb1\xc0\x94\xa3\xa4\x3e\x3e\x84\x40\xc7\xd4\xfa\x3f\x92\x32\x07\xe9\x33\xdd\xa2\xae\x49\x15\x39\xae\xb0\x18\x5a\xdc\xd1\xc9\xa6\x21\x7d\x4e\xc8\x5b\xfd\xf3\xf5\xe5\xcb\xb7\xd5\xe3\x8f\x00\x42\xf5\xcd\x1c\x49\xaf\xd6\x17\x79\x08\xbb\xfa\x1d\x00\x00\xff\xff\xfd\xfd\xd2\x06\x02\x05\x00\x00")

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

	info := bindata_file_info{name: "recover.tpl", size: 1282, mode: os.FileMode(438), modTime: time.Unix(1424471280, 0)}
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

