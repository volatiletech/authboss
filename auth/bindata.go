package auth

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
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
	name    string
	size    int64
	mode    os.FileMode
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

var _views_login_css = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x94\x55\xdd\x4e\xe3\x3a\x10\xbe\x47\xe2\x1d\x2c\xa1\x23\x40\x6a\x82\x73\x5a\x5a\x48\x85\xce\xd9\x9b\x7d\x80\xbd\x5d\x71\xe1\xc4\x4e\x32\xc2\xf1\x58\xb6\x4b\x0b\x2b\xde\x7d\x9d\xe6\xa7\x49\x9a\x52\xa8\xdb\x1b\xcf\x8f\x67\xbe\xf9\xe6\xeb\xff\x50\x6a\x34\x8e\x6c\x8c\xbc\x29\x9c\xd3\xf1\xdd\x5d\x86\xca\xd9\x30\x47\xcc\xa5\x60\x1a\x6c\x98\x62\x79\x97\x5a\xfb\x5f\xc6\x4a\x90\x6f\x4f\xbf\x30\x41\x87\xf1\x82\xd2\x59\x44\xe9\xed\xfa\xf2\xe2\xf2\x22\x41\xfe\x46\xfe\x5c\x5e\x10\xff\xa9\xe2\x83\xda\x37\x26\xd7\xb5\xf7\xf5\x8c\x58\xa6\x6c\x60\x85\x81\xcc\x47\x7c\x54\x41\xa1\xc4\x1c\x54\x90\x32\xc3\xdb\x58\xcd\x38\x07\x95\xc7\x64\x41\xf5\x6e\x5d\xdf\x6d\x81\xbb\x22\x26\xff\xae\x16\xdd\x55\xc2\xd2\x97\xdc\xe0\x46\xf1\x20\x45\x89\x26\x26\x57\x3f\x57\xd5\x69\xec\x25\x33\x3e\x73\x4c\x28\x61\x1b\x87\x24\x3a\x24\x4b\xd0\x70\x61\x02\xc3\x38\x6c\xac\x4f\xda\x33\xec\x02\x5b\x30\x8e\x5b\x1f\xa6\x77\x95\x65\xff\x33\x79\xc2\x6e\xe8\x8c\x34\xdf\x70\x7e\xdb\x04\xe0\xab\x30\x99\xac\xdc\x0b\xe0\x5c\xa8\xa9\xae\x8a\x68\x00\xca\x56\x40\x5e\xb8\xd8\xd7\x43\x9b\x24\x4e\xec\x5c\xc0\x24\xe4\xbe\xd8\x54\x28\x27\xcc\xba\xe7\x6f\xe1\x5d\xf8\x1a\xc3\xb9\x28\xa7\xb2\x83\xd2\x1b\xf7\xdb\xbd\x69\xf1\x64\x37\x49\x09\xee\xb9\x7d\xad\x81\xcc\xbf\xf3\x4f\x93\x8f\x83\xd5\x92\xf9\x81\x24\x12\xd3\x97\x01\x4c\x81\x1f\x90\xc3\x32\xee\xc3\xa4\xd1\x82\x03\xf4\x55\x19\x21\x99\x83\x57\x71\xa6\x80\xaa\x91\xe7\x59\xff\x46\x33\x6b\xb7\x1e\xed\xae\xa8\xa2\xe9\x7e\x71\x98\x63\xaf\xcb\x68\x39\x1e\x78\xaf\xfa\xd3\x85\x7a\x4c\x93\x17\xf0\x18\x6a\x2d\x98\x61\x2a\xf5\xa9\x14\x2a\x71\x44\x14\x4f\x91\x2c\xcb\x06\x2c\xf0\x89\xfc\x80\x2d\x4a\xe0\xe4\x8a\x3f\x56\x67\xc8\x12\x87\x7a\xe0\x93\xd2\xea\xac\x47\x54\xa5\xe4\x61\xc8\x22\x78\xdf\xdf\x37\x49\xfc\x55\x5b\x6b\x89\xef\xc1\x49\x8f\xb3\xe8\xc6\x45\x45\xb9\x69\x8c\x6b\x5b\x8b\xf4\x44\x7b\xc9\x63\x75\x3e\x6f\x8f\xd1\xea\x1c\x15\xdb\x2c\x05\x28\x2b\x9c\x6f\x36\x1a\x2e\xc6\xfe\x84\xd1\xed\x68\x1e\xdf\x8f\xfc\x5e\x44\x0f\xad\xb6\xeb\xaf\xec\x52\x34\xe2\x5e\x27\x53\x3f\x0c\x30\x39\x56\xa9\xa3\xc5\x5d\x75\x8b\xdb\x92\x79\x7e\xa0\xed\x11\x21\xfa\x13\xad\x17\x74\x3c\xa0\x03\x8f\x5b\x19\x3b\x70\x74\xdf\x4e\xa7\x48\x7b\x28\x4e\x00\x77\x2c\x86\x0b\xfe\x48\xb3\xf1\xca\xd6\x25\x4c\x33\xe5\x50\xc8\xb9\x67\xe7\x9f\x3c\x3b\xbf\x5f\x31\xf1\x30\xc5\x65\x36\x18\x12\x17\x29\x1a\x56\xeb\x4b\x6f\x59\xdb\x34\xcb\xe5\x72\x0a\xfc\xc5\x79\xd5\xec\x54\x0e\x94\x04\x25\x82\xbe\xd8\xa1\x66\x29\x38\x6f\xa3\x61\x9b\xde\x79\xc1\x68\x75\xae\x31\x13\xc1\xac\xf0\x2e\xf7\x76\xb2\x8d\x21\x7a\x5d\xca\x68\xe4\x5c\x08\xa9\x4f\x6b\xf1\x97\x88\x5a\xff\x33\x7d\xfc\x0d\x00\x00\xff\xff\x8c\x99\xe5\x66\xa0\x07\x00\x00")

func views_login_css_bytes() ([]byte, error) {
	return bindata_read(
		_views_login_css,
		"views/login.css",
	)
}

func views_login_css() (*asset, error) {
	bytes, err := views_login_css_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "views/login.css", size: 1952, mode: os.FileMode(438), modTime: time.Unix(1420431129, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _views_login_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x8c\x52\x41\x4e\x85\x30\x10\xdd\x9b\x78\x87\x66\x5c\x7f\x1b\xf7\x85\xa5\xab\xbf\x30\x26\x1e\xa0\xc0\x7c\xda\x58\x28\xce\xb4\x5f\xd9\x79\x16\x8f\xe6\x49\x2c\xd8\xa2\xc4\x98\x7c\x36\xbc\xe9\x3c\xde\x3c\xde\x54\x99\x30\xb8\xfa\xfa\x4a\xa4\x47\x39\x3b\x3e\x8b\x30\x4f\x58\x41\xc0\xb7\x20\x5b\x66\x10\x84\xae\x02\x0e\xb3\x43\x36\x88\x01\x84\x21\x3c\x55\x20\x75\x0c\xa6\xf1\xcc\xb7\x2b\x4b\x26\x0d\xd5\xf8\x6e\x5e\xde\x9d\x3d\x8b\xd6\x69\xe6\x0a\x9c\xef\xed\x78\x68\x35\x75\x50\xa6\x98\xbb\xfa\xe8\xfb\x83\x1d\x95\x4c\x50\x35\x54\x1a\x27\x4f\x43\xc6\x6b\x6d\xc7\x29\x86\x5f\x7e\x40\x8c\x7a\x48\x38\x32\xd2\x82\x40\x4c\x4e\xb7\x68\xbc\xeb\x90\x2a\x78\xda\x8e\x09\x5f\xa2\x25\xec\xd2\x67\x14\x11\xfe\xd3\x9c\x92\xc3\x57\x9f\x9c\x65\xdd\x9f\x7a\xa7\xfb\xb0\x1d\x5f\xa8\xcb\xb1\x19\xec\xe6\x76\x4d\x00\x76\x79\x88\xef\x54\x0a\xef\xac\x5d\x4c\xc4\xe3\x4a\x2c\x61\xc8\x9c\x46\x2e\xff\x44\x6a\xd0\x4d\x3b\x07\x3a\x2f\xe6\x06\xea\x47\xec\x2d\x07\x24\x25\x75\x2d\x3e\xdf\x3f\x76\xcd\x7b\x4f\xbd\x0f\xa2\xfc\xd5\xc2\x29\x23\xd3\x90\x65\x7d\xb2\xec\x51\xe6\xcb\xf1\x15\x00\x00\xff\xff\x9b\xc0\xd6\xae\x25\x02\x00\x00")

func views_login_tpl_bytes() ([]byte, error) {
	return bindata_read(
		_views_login_tpl,
		"views/login.tpl",
	)
}

func views_login_tpl() (*asset, error) {
	bytes, err := views_login_tpl_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "views/login.tpl", size: 549, mode: os.FileMode(438), modTime: time.Unix(1420432724, 0)}
	a := &asset{bytes: bytes, info: info}
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
	"views/login.css": views_login_css,
	"views/login.tpl": views_login_tpl,
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
	Func     func() (*asset, error)
	Children map[string]*_bintree_t
}

var _bintree = &_bintree_t{nil, map[string]*_bintree_t{
	"views/login.css": &_bintree_t{views_login_css, map[string]*_bintree_t{}},
	"views/login.tpl": &_bintree_t{views_login_tpl, map[string]*_bintree_t{}},
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
