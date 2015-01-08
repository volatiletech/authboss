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

var _views_login_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x8c\x52\xc1\x4e\xec\x30\x0c\xbc\x3f\xe9\xfd\x43\x64\xce\x4b\xc4\x3d\xed\x91\xd3\x1e\x10\x12\x1f\x90\xb6\xde\x26\x22\x6d\x82\x9d\x2c\xf4\xef\x49\x4b\x52\xb6\x42\x48\xf4\x92\xb1\x33\x1d\x4f\xc7\x55\x26\x4e\xae\xfd\xff\x4f\xe4\x47\x39\x3b\xbf\x8a\xb8\x04\x6c\x20\xe2\x47\x94\x3d\x33\x08\x42\xd7\x00\xc7\xc5\x21\x1b\xc4\x08\xc2\x10\x5e\x1a\x90\x3a\x45\xd3\x79\xe6\xfb\x8d\x25\xb3\x86\xea\xfc\xb0\xac\xe7\x60\xaf\xa2\x77\x9a\xb9\x01\xe7\x47\x3b\x9f\x7a\x4d\x03\xd4\x29\xe6\xa1\x3d\xfb\xf1\x64\x67\x25\x33\x54\x1d\xd5\x8b\x8b\xa7\xa9\xe0\xad\xb6\x73\x48\xf1\xc6\x0f\x88\x59\x4f\x19\x27\x46\x5a\x11\x88\xe0\x74\x8f\xc6\xbb\x01\xa9\x81\x97\xbd\x4d\xf8\x96\x2c\xe1\x90\x5f\xa3\x84\xf0\x9b\x66\xc8\x0e\xdf\x7d\x76\x56\x74\xbf\xeb\x83\xee\xd3\xde\xfe\xa3\x2e\xa7\x6e\xb2\xbb\xdb\x2d\x01\x38\xe4\x21\xbe\x52\xa9\xbc\xab\x76\x29\x13\xcf\x1b\xb1\x86\x21\x4b\x1a\xa5\xfc\x11\xa9\x41\x17\x0e\x0e\x74\x59\xcc\x1d\xb4\xcf\x38\x5a\x8e\x48\x4a\xea\xf6\xb6\xff\xe8\x69\xf4\x51\xd4\x0f\x5a\xaf\xeb\xb4\xac\xbf\x6e\x6e\x3f\xeb\x2a\x65\xf9\x3f\x3e\x03\x00\x00\xff\xff\x8d\x1c\x54\xbc\x28\x02\x00\x00")

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

	info := bindata_file_info{name: "views/login.tpl", size: 552, mode: os.FileMode(438), modTime: time.Unix(1420700832, 0)}
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
