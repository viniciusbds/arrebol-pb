package allowlist

import (
	"bufio"
	"os"

	"github.com/google/logger"
)

const (
	ListFilePath = "ALLOW_LIST_PATH"
)

type AllowList struct {
	list          []string
	nextAvailable int
}

func NewAllowList() AllowList {
	list, err := loadSourceFile()
	if err != nil {
		logger.Fatal(err)
	}
	return AllowList{list: list}
}

func (l *AllowList) contains(workerId string) bool {
	for _, current := range l.list {
		if current == workerId {
			return true
		}
	}
	return false
}

func loadSourceFile() ([]string, error) {
	file, err := os.Open(os.Getenv(ListFilePath))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ids []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ids = append(ids, scanner.Text())
	}
	return ids, scanner.Err()
}

func (l *AllowList) GetNextAvailableWorkerID() string {
	workerId := l.list[l.nextAvailable]
	l.nextAvailable++
	return workerId
}
