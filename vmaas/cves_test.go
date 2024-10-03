package vmaas

import (
	"testing"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
)

func TestPkgDetail2Nevra(t *testing.T) {
	c := mockCache()
	pkgDetail := c.PackageDetails[PkgID(1)]
	nevra := c.pkgDetail2Nevra(pkgDetail)
	assert.Equal(t, "kernel-1:1-1.x86_64", nevra)
}

func TestErrataIDs2Names(t *testing.T) {
	c := mockCache()
	errataNames := c.errataIDs2Names([]int{1, 2})
	assert.Equal(t, 2, len(errataNames))
}

func TestPackageIDs2Nevras(t *testing.T) {
	c := mockCache()
	binPackages, sourcePackages := c.packageIDs2Nevras([]int{1, 3})
	assert.Equal(t, 1, len(binPackages))
	assert.Equal(t, 1, len(sourcePackages))
	assert.Equal(t, "kernel-1:1-1.x86_64", binPackages[0])
	assert.Equal(t, "kernel-devel-1:1-1.src", sourcePackages[0])
}

func TestGetSortedCveIDs(t *testing.T) {
	req := mockCvesRequest()
	reqWithoutReq := &CvesRequest{}
	c := mockCache()

	cveIDs, err := req.getSortedCveIDs(c.CveDetail)
	assert.NoError(t, err)
	assert.Equal(t, "CVE-2024-1111111", cveIDs[0])
	assert.Equal(t, "CVE-2024-1234", cveIDs[1])
	assert.Equal(t, "CVE-2024-21345", cveIDs[2])

	_, err = reqWithoutReq.getSortedCveIDs(c.CveDetail)
	assert.Error(t, err)
}

func TestFilterCveIDs(t *testing.T) {
	cveIDs := []string{"CVE-2024-1234", "CVE-2024-21345", ""}
	c := mockCache()

	// usual case
	filteredIDs := filterCveIDs(cveIDs, &CvesRequest{}, c.CveDetail)
	assert.Equal(t, 2, len(filteredIDs))

	// RHOnly
	req := &CvesRequest{RHOnly: true}
	filteredIDs = filterCveIDs(cveIDs, req, c.CveDetail)
	assert.Equal(t, 1, len(filteredIDs))
	assert.Equal(t, "CVE-2024-21345", filteredIDs[0])

	// With some errata associated only
	req = &CvesRequest{AreErrataAssociated: true}
	filteredIDs = filterCveIDs(cveIDs, req, c.CveDetail)
	assert.Equal(t, 1, len(filteredIDs))
	assert.Equal(t, "CVE-2024-1234", filteredIDs[0])

	// With modified date before req.ModifiedSince
	req = &CvesRequest{ModifiedSince: "2024-10-03T15:01:01Z"}
	filteredIDs = filterCveIDs(cveIDs, req, c.CveDetail)
	assert.Equal(t, 1, len(filteredIDs))
	assert.Equal(t, "CVE-2024-1234", filteredIDs[0])

	// With published date before req.PublishedSince
	req = &CvesRequest{PublishedSince: "2024-10-03T15:01:01Z"}
	filteredIDs = filterCveIDs(cveIDs, req, c.CveDetail)
	assert.Equal(t, 1, len(filteredIDs))
	assert.Equal(t, "CVE-2024-1234", filteredIDs[0])
}

func TestLoadCveProperties(t *testing.T) {
	c := mockCache()
	cveID := "CVE-2024-1111111"
	cvePropertiesMap := c.loadCveProperties([]string{cveID})
	assert.Equal(t, 1, len(cvePropertiesMap))
	assert.Equal(t, cveID, cvePropertiesMap[cveID].Synopsis)
}

func TestCves(t *testing.T) {
	req := &CvesRequest{}
	c := mockCache()

	// empty cve list
	_, err := req.cves(c)
	assert.Error(t, err)
}

func mockCache() *Cache {
	modifiedDate := "2024-10-03T11:44:00+02:00"
	publishedDate := "2024-10-03T11:44:00+02:00"
	return &Cache{
		ID2Packagename: map[NameID]string{1: "kernel", 2: "kernel-devel"},

		ID2Evr: map[EvrID]utils.Evr{
			1: {Epoch: 1, Version: "1", Release: "1"},
			2: {Epoch: 0, Version: "2", Release: "2"},
		},

		Arch2ID: map[string]ArchID{
			"x86_64": 1,
			"src":    2,
		},
		ID2Arch: map[ArchID]string{
			1: "x86_64",
			2: "src",
		},

		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 1}, // kernel-1:1-1
			2: {NameID: 1, EvrID: 2, ArchID: 1}, // kernel-0:2-2
			3: {NameID: 2, EvrID: 1, ArchID: 2}, // kernel-devel-1:1-1
		},

		ErratumID2Name: map[ErratumID]string{
			1: "RHSA-2024:0042",
			2: "RHSA-2024:1111",
		},

		CveDetail: map[string]CveDetail{
			"CVE-2024-21345": {
				Source: "Red Hat",
				CveDetailCommon: CveDetailCommon{
					ModifiedDate:  &modifiedDate,
					PublishedDate: &publishedDate,
				},
			},
			"CVE-2024-1234": {
				ErrataIDs: []int{1, 2},
			},
			"CVE-2024-1111111": {},
		},

		DBChange: DBChange{LastChange: "2024-10-02T16:08:00+02:00"},
	}
}

func mockCvesRequest() *CvesRequest {
	return &CvesRequest{
		CveIDs:              []string{"CVE-2024-21345", "CVE-2024-1234", "CVE-2024-1111111"},
		ModifiedSince:       "2024-10-02T16:08:00+02:00",
		PublishedSince:      "2024-10-02T16:08:00+02:00",
		RHOnly:              false,
		AreErrataAssociated: false,
		PageNumber:          1,
		PageSize:            5000,
	}
}
