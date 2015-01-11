package auth

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

var _views_login_tpl = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x8c\x52\x4f\x4f\xfc\x20\x10\xbd\xff\x92\xdf\x77\xc0\xf1\x8c\x64\xef\x94\xa3\xa7\x3d\x18\x13\x3f\x00\x2d\xb3\x85\x48\x4b\x1d\x60\x75\xbf\xbd\xb4\xc2\xba\x8d\x31\xb1\x97\xf9\xc3\xe3\xcd\xeb\x1b\xa4\x4d\x93\x57\xff\xff\x49\x8b\xda\x94\xc8\xca\x27\xef\x38\x97\xde\xcd\xaf\x2c\x5d\x16\xec\x20\xe1\x47\x12\x43\x8c\xc0\x08\x7d\x07\x31\x5d\x3c\x46\x8b\x98\x80\x59\xc2\x53\x07\x42\xe7\x64\xfb\x10\xe3\xc3\x86\x12\x8a\xf3\x95\x52\x54\x4e\xd9\x07\x73\x59\xa3\x71\x67\x36\x78\x1d\x63\x07\x3e\x8c\x6e\xe6\x83\x26\x03\x6d\xaa\x3d\xa8\x63\x18\xb9\x9b\xcb\xc5\x83\x92\x3d\xb5\x83\x53\xa0\xa9\xe6\x5b\xed\xe6\x25\xa7\x1b\x6d\xc0\x66\x3d\x95\x3c\x47\xa4\x35\x03\xb6\x78\x3d\xa0\x0d\xde\x20\x75\xf0\x72\x6d\x13\xbe\x65\x47\x68\xca\x35\xca\x08\xbf\x71\x2e\x45\xe1\x7b\x28\xca\x2a\xef\x77\xbd\xe3\x7d\xba\xb6\xff\xc8\x1b\x73\x3f\xb9\xab\xda\xcd\x01\xd8\xf9\xc1\xbe\x5c\x69\xb8\xb3\xf6\xb9\x00\x8f\x1b\xb0\x99\x21\xaa\x1b\xb5\xfc\x61\xa9\x45\xbf\xec\x14\xe8\xba\xa4\x7b\x50\xcf\x38\xba\x98\x90\xa4\xd0\xea\xb6\xff\x18\x68\x0c\x89\xb5\x1f\x5a\x8f\xdb\xb4\xc2\xbf\xad\xb2\xc5\xb6\x4a\x51\xdf\xcd\x67\x00\x00\x00\xff\xff\x0b\x6f\xce\x8d\x40\x02\x00\x00")

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

	info := bindata_file_info{name: "views/login.tpl", size: 576, mode: os.FileMode(438), modTime: time.Unix(1420956750, 0)}
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
	Func func() (*asset, error)
	Children map[string]*_bintree_t
}
var _bintree = &_bintree_t{nil, map[string]*_bintree_t{
	"views/login.tpl": &_bintree_t{views_login_tpl, map[string]*_bintree_t{
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

