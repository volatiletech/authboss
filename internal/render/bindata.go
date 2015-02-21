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

var _recover_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xd4\x54\x4d\x8f\x9b\x30\x10\xbd\xf3\x2b\xa6\xd6\x5e\xbd\xdc\x2b\xe0\x12\xb5\xb7\x7e\x68\x3f\xa4\x5e\x0d\x98\x60\xc5\xd8\x68\x30\x51\x57\x16\xff\xbd\x43\x0c\x1b\xc2\x92\x36\x6d\xd5\x43\x23\x11\x0d\x66\xfc\x9e\xe7\xbd\xf1\x24\x95\xc5\x06\x44\xe1\x94\x35\x29\x8b\x51\x16\xf6\x28\x91\x41\x23\x5d\x6d\xcb\x94\x7d\xfd\xf2\xf8\xc4\xb2\x08\xe8\x97\x28\xd3\xf6\x0e\xdc\x4b\x2b\x53\xe6\xe4\x77\xc7\xc0\x88\x86\xe2\xbe\x93\x38\x46\x0c\x5a\x2d\x0a\x59\x5b\x5d\x4a\x4c\xd9\xf3\xeb\xf2\x51\xe8\x9e\xf2\xbc\xbf\x9f\x53\x87\x81\x41\x9c\x25\x39\xd2\xff\xcf\xc1\x0b\x6b\x2a\x85\xcd\xf3\x36\xc7\x2e\x7c\x85\x2d\xae\xd5\xce\xb7\x94\x79\xef\x9c\x35\x13\x67\xd7\xe7\x8d\x72\x2c\x7b\x08\x0a\x24\x71\xf8\x3a\xa5\x0a\xa8\x51\x56\x24\x90\xb6\x7b\x65\x58\xb6\x13\xa6\x90\x3a\x89\x45\x16\x25\xf1\x28\x61\x16\x45\x51\xf2\x8e\x73\xf8\x0d\x41\xbd\xbf\x9b\xf5\xf8\x80\xd8\xc1\xfb\x14\xee\x29\xf8\x24\xda\x85\x4e\x81\xbf\x54\x47\x28\xb4\xe8\xba\x94\x8d\xf8\x7c\x8f\xb6\x6f\xbd\x57\x15\x5c\x40\x0c\x03\xd4\xa2\xe3\x12\xd1\xa2\xf7\xd2\x94\x54\x74\xe0\x5a\xa3\x9c\xe4\x0e\x30\x8b\x8c\x53\x56\xd7\x0a\xb3\x91\xc6\x45\x59\x5a\x2a\x3d\x51\xaf\x27\x11\x50\x09\x3e\xf2\xd3\x6a\xac\xe8\x19\xb7\xae\xd0\x82\xaf\xcb\xb3\x93\x2f\x0e\xad\x66\x7f\xd7\x49\x97\xb6\x9e\x6b\x8c\xa9\xc8\xf3\xab\xf7\x28\xcc\x5e\xc2\x1d\x49\x32\xea\xbb\x52\xeb\x7a\xe1\xb5\xd4\x2d\xcf\xb5\x2d\x0e\x2c\xf3\xbe\x45\x65\xdc\x09\x64\x18\xd6\x55\x4e\x3a\x47\x0b\xf6\xd9\xdd\x55\x07\xae\x4d\x7e\xd3\xa0\xbf\xf4\x7a\x03\xf0\x7f\xb7\xfc\xcf\xef\xf7\x6e\xeb\x7e\xdf\xdc\x08\x9b\x52\xfe\xa3\x7e\x18\xc3\x8b\x91\x33\x81\xe6\xce\x00\x3d\x9c\xe0\x1a\x81\x2f\xa7\x38\x70\xdc\x38\x94\x56\x38\x5a\x99\xc3\x55\x90\xeb\x13\x6c\x61\x5a\xd8\x51\xab\xb2\x94\x66\x76\x88\xa4\xfe\xf6\xf8\xf0\xf1\xf3\xa4\xf1\xd9\x80\x71\xf5\xc9\x1e\xa4\x99\xa4\x9f\x26\x21\x70\x9e\xfd\x08\x00\x00\xff\xff\x94\x24\x92\xf9\x57\x06\x00\x00")

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

	info := bindata_file_info{name: "recover.tpl", size: 1623, mode: os.FileMode(438), modTime: time.Unix(1424541421, 0)}
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

