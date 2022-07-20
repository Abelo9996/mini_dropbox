package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(false)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytes2UUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func TestInit1(t *testing.T) {
	clear()
	_, err := InitUser("test", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = InitUser("test1", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = InitUser("test", "test2")
	if err == nil {
		t.Error("This should pass!")
		return
	}
}

func TestInit2(t *testing.T) {
	clear()
	_, err := InitUser("test", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = InitUser("test1", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
}

func TestInit3(t *testing.T) {
	clear()
	_, err := InitUser("", "test")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = InitUser("test1", "")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = InitUser("", "")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
}

func TestGet1(t *testing.T) {
	clear()
	_, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = GetUser("a", "teSt")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
}

func TestGet2(t *testing.T) {
	clear()
	_, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = GetUser("a", "t eSt")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
}

func TestGet3(t *testing.T) {
	clear()
	_, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = GetUser("a", "t eSt")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
}

func TestGet4(t *testing.T) {
	clear()
	a, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	b, err := GetUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	if !reflect.DeepEqual(a, b) {
		t.Error("They should be equal!")
		return
	}
}

func TestGet5(t *testing.T) {
	clear()
	_, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	clear()
	_, err = GetUser("a", "test")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
}

func TestGet6(t *testing.T) {
	clear()
	_, err := InitUser("a", "test_")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = GetUser("a", "t eSt")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
}

func TestGet7(t *testing.T) {
	clear()
	a, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = InitUser("a1", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	c, err := GetUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	if !reflect.DeepEqual(a, c) {
		t.Error("They should be equal!")
		return
	}
}

func TestGet8(t *testing.T) {
	clear()
	_, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	clear()
	a, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	c, err := GetUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	if !reflect.DeepEqual(a, c) {
		t.Error("They should be equal!")
		return
	}
}

func TestGet9(t *testing.T) {
	clear()
	_, err := InitUser("a", "test")
	if err != nil {
		t.Error("Failed incorrectly!")
		return
	}
	_, err = InitUser("a", "test")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
	clear()
	_, err = GetUser("a", "test")
	if err == nil {
		t.Error("Failed incorrectly!")
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestStorage1(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	v3, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) || !reflect.DeepEqual(v, v3) || !reflect.DeepEqual(v2, v3) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestStorage2(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err2 := u.LoadFile("file2")
	if err2 == nil {
		t.Error("Failed to upload and download", err2)
		return
	}
}

func TestStorage3(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u1, err := InitUser("alex", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err2 := u1.LoadFile("file1")
	if err2 == nil {
		t.Error("Failed to upload and download", err2)
		return
	}
}

func TestStorage4(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("this is a test")
	u.StoreFile("", v)

	test, err2 := u.LoadFile("")
	if !reflect.DeepEqual(v, test) {
		t.Error("Failed to upload and download", err2)
		return
	}
}

func TestStorage5(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("")
	u.StoreFile("file1", v)

	test, err2 := u.LoadFile("file1")
	if len(test) != 0 {
		t.Error("Failed to upload and download", err2)
		return
	}
}

func TestStorage6(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u1, err := InitUser("alex", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("this is a test")
	u.StoreFile("test", v)
	u1.StoreFile("test", v)

	test, err2 := u.LoadFile("test")
	if err2 != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	test1, err2 := u1.LoadFile("test")
	if err2 != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	if !reflect.DeepEqual(test1, test) {
		t.Error("Failed to upload and download", err2)
		return
	}
}

func TestAppendFile1(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("this is a test")
	err2 := u.AppendFile("file1", v)
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestAppendFile2(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("this is a test")
	u.StoreFile("file1", v)
	v1 := []byte("2")
	err2 := u.AppendFile("file1", v1)
	if err2 != nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
	test, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	if !reflect.DeepEqual([]byte("this is a test2"), test) {
		t.Error("Failed to upload and download", err2)
		return
	}
}

func TestAppendFile3(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("this is a test")
	u.StoreFile("", v)
	v1 := []byte("2")
	err2 := u.AppendFile("", v1)
	if err2 != nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
	v2 := []byte("2")
	err2 = u.AppendFile("", v2)
	if err2 != nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
	test, err2 := u.LoadFile("")
	if err2 != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	if !reflect.DeepEqual([]byte("this is a test22"), test) {
		t.Error("Failed to upload and download", err2)
		return
	}
}

func TestAppendFile4(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u1, err := InitUser("alex", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("this is a test")
	u.StoreFile("", v)
	v = []byte("this is a test")
	u1.StoreFile("", v)
	v1 := []byte("2")
	err2 := u.AppendFile("", v1)
	if err2 != nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
	v1 = []byte("3")
	err2 = u1.AppendFile("", v1)
	if err2 != nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
	v2 := []byte("2")
	err2 = u.AppendFile("", v2)
	if err2 != nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
	v2 = []byte("3")
	err2 = u1.AppendFile("", v2)
	if err2 != nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
	test, err2 := u.LoadFile("")
	if err2 != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	test1, err2 := u1.LoadFile("")
	if err2 != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	if !reflect.DeepEqual([]byte("this is a test22"), test) || !reflect.DeepEqual([]byte("this is a test33"), test1) {
		t.Error("Failed to upload and download", err2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestShare1(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u3, err2 := InitUser("bob1", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	accessToken, err = u2.ShareFile("file2", "bob1")
	err = u3.ReceiveFile("file3", "bob", accessToken)
	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) || !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestShare3(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u3, err2 := InitUser("bob1", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u4, err2 := InitUser("bob2", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	accessToken, err = u2.ShareFile("file2", "bob1")
	err = u3.ReceiveFile("file3", "bob", accessToken)
	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) || !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	accessToken, err = u2.ShareFile("file2", "bob2")
	err = u4.ReceiveFile("file4", "bob", accessToken)
	v4, err := u4.LoadFile("file4")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) || !reflect.DeepEqual(v2, v3) || !reflect.DeepEqual(v4, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestShare2(t *testing.T) {
	clear()
	randinput := int(userlib.RandomBytes(1)[0])
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u3, err2 := InitUser("bob1", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u4, err2 := InitUser("bob2", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob123")
	if err == nil {
		t.Error("Failed to share the a file", err)
		return
	}
	accessToken, err = u.ShareFile("file132", "bob")
	if err == nil {
		t.Error("Failed to share the a file", err)
		return
	}
	accessToken, err = u.ShareFile("file132", "bob123")
	if err == nil {
		t.Error("Failed to share the a file", err)
		return
	}
	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice123", accessToken)
	if err == nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	err = u3.ReceiveFile("file2", "alice", accessToken)
	if err == nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", bytes2UUID(userlib.RandomBytes(randinput)))
	if err == nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	accessToken, err = u.ShareFile("file1", "bob")
	if err == nil {
		t.Error("Failed to share the a file", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	accessToken, err = u2.ShareFile("file2", "bob1")
	err = u3.ReceiveFile("file3", "bob", accessToken)
	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) || !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	accessToken, err = u2.ShareFile("file2", "bob2")
	err = u4.ReceiveFile("file4", "bob", accessToken)
	v4, err := u4.LoadFile("file4")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) || !reflect.DeepEqual(v2, v3) || !reflect.DeepEqual(v4, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}
func TestRevoke1(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u3, err2 := InitUser("bob1", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	accessToken, err = u2.ShareFile("file2", "bob1")
	err = u3.ReceiveFile("file3", "bob", accessToken)
	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) || !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	err = u.RevokeFile("file", "testusername")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	err = u.RevokeFile("file123", "bob")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	err = u.RevokeFile("file1", "bob1")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	err = u.RevokeFile("file1", "alice")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	err = u2.RevokeFile("file2", "bob1")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	err = u.RevokeFile("file1", "bob")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v3, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v3, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
}

func TestMap(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	testmap := userlib.DatastoreGetMap()
	for ouruuid, _ := range testmap {
		userlib.DatastoreSet(ouruuid, []byte(ouruuid.String()))
	}
	load, throwerror := u.LoadFile("file1")
	if throwerror == nil {
		t.Error("Should not throw error!")
		return
	}
	if reflect.DeepEqual(v, load) {
		t.Error("incorrect test!")
		return
	}
}
