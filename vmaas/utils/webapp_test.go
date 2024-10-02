package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTryExpandRegexPattern(t *testing.T) {
	regexLabel := []string{`CVE-2024-1\d+`}
	inLabels := []string{"CVE-2024-1234", "CVE-2024-21345"}
	labelDetails := map[string]int{
		"CVE-2024-1234":  0,
		"CVE-2024-12345": 0,
		"CVE-2024-21345": 0,
	}

	// empty slice
	outLabels := TryExpandRegexPattern([]string{}, labelDetails)
	assert.Equal(t, 0, len(outLabels))

	// with a single lable that is not a regex pattern
	outLabels = TryExpandRegexPattern(inLabels[0:1], labelDetails)
	assert.Equal(t, inLabels[0], outLabels[0])

	// more labels in inLabels
	outLabels = TryExpandRegexPattern(inLabels, labelDetails)
	assert.Equal(t, len(inLabels), len(outLabels))

	// with regex
	outLabels = TryExpandRegexPattern(regexLabel, labelDetails)
	assert.Equal(t, 2, len(outLabels))
}

func TestPaginate(t *testing.T) {
	slice := []int{42, 43, 44, 45, 46}

	// empty slice
	subslice, paginationDetails := Paginate([]int{}, 1, 2)
	assert.Equal(t, 0, len(subslice))
	assert.Equal(t, 1, paginationDetails.PageNumber)
	assert.Equal(t, 0, paginationDetails.PageSize)
	assert.Equal(t, 1, paginationDetails.TotalPages)

	// use default values of pageNumber and pageSize
	subslice, paginationDetails = Paginate(slice, 0, -1)
	assert.Equal(t, len(slice), len(subslice))
	assert.Equal(t, 1, paginationDetails.PageNumber)
	assert.LessOrEqual(t, paginationDetails.PageSize, 5000)

	// usual case
	subslice, paginationDetails = Paginate(slice, 2, 2)
	assert.Equal(t, 2, len(subslice))
	assert.Equal(t, 44, subslice[0])
	assert.Equal(t, 45, subslice[1])
	assert.Equal(t, 2, paginationDetails.PageNumber)
	assert.Equal(t, 2, paginationDetails.PageSize)
	assert.Equal(t, 3, paginationDetails.TotalPages)

	// the last page
	subslice, paginationDetails = Paginate(slice, 2, 3)
	assert.LessOrEqual(t, len(subslice), 3)
}
