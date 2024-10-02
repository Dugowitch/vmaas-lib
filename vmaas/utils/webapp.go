package utils

import (
	"math"
	"regexp"
	"strings"
)

const (
	DefaultPageNumber = 1
	DefaultPageSize   = 5000
)

type PaginationDetails struct {
	PageNumber int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalPages int `json:"pages"`
}

// TryExpandRegexPattern treats the item in a single-label slice like a regex pattern
// and returns all matching labels from dataByLabels, otherwise it returns inLabels.
func TryExpandRegexPattern[T any](inLabels []string, dataByLabels map[string]T) []string {
	if len(inLabels) != 1 {
		return inLabels
	}

	pattern := inLabels[0]
	if !strings.HasPrefix(pattern, "^") {
		pattern = "^" + pattern
	}
	if !strings.HasSuffix(pattern, "$") {
		pattern += "$"
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return inLabels
	}

	outLabels := make([]string, 0, len(dataByLabels))
	for label := range dataByLabels {
		matched := re.Match([]byte(label))
		if matched {
			outLabels = append(outLabels, label)
		}
	}
	return outLabels
}

// Paginate returns pageSize-long sub-slice of items corresponding to the pageNumber.
// For the last page, there may be fewer than pageSize items.
func Paginate[T any](slice []T, pageNumber, pageSize int) ([]T, PaginationDetails) {
	if pageNumber <= 0 {
		pageNumber = DefaultPageNumber
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}

	start := (pageNumber - 1) * pageSize
	if start > len(slice) {
		start = len(slice)
	}
	end := pageNumber * pageSize
	if end > len(slice) {
		end = len(slice)
	}
	subslice := slice[start:end]

	totalPages := int(math.Ceil(float64(len(slice))/float64(pageSize) + 1e-6))

	paginationDetails := PaginationDetails{
		PageNumber: pageNumber,
		PageSize:   len(subslice),
		TotalPages: totalPages,
	}
	return subslice, paginationDetails
}
