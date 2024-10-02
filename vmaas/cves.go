package vmaas

import (
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type (
	CveDetailMap     map[string]CveDetail
	CvePropertiesMap map[string]CveProperties
)

type CveProperties struct {
	Synopsis       string   `json:"synopsis"`
	Errata         []string `json:"errata_list"`
	Packages       []string `json:"package_list"`
	SourcePackages []string `json:"source_package_list"`
	CveDetailCommon
}

type Cves struct {
	Cves       CvePropertiesMap `json:"cve_list"`
	LastChange string           `json:"last_change"`
}

func (c *Cache) pkgDetail2Nevra(pkgDetail PackageDetail) string {
	name := c.ID2Packagename[pkgDetail.NameID]
	evr := c.ID2Evr[pkgDetail.EvrID]
	arch := c.ID2Arch[pkgDetail.ArchID]
	return utils.JoinNevra(name, evr, arch)
}

func (c *Cache) errataIDs2Names(eids []int) []string {
	names := make([]string, 0, len(eids))
	for _, eid := range eids {
		names = append(names, c.ErratumID2Name[ErratumID(eid)])
	}
	return names
}

func (c *Cache) packageIDs2Nevras(pkgIDs []int) ([]string, []string) {
	binPackages := make([]string, 0, len(pkgIDs))
	sourcePackages := make([]string, 0, len(pkgIDs))
	sourceArchID := c.Arch2ID["src"]
	for _, pkgID := range pkgIDs {
		pkgDetail := c.PackageDetails[PkgID(pkgID)]
		nevra := c.pkgDetail2Nevra(pkgDetail)
		if nevra == "" {
			continue
		}
		if pkgDetail.ArchID == sourceArchID {
			sourcePackages = append(sourcePackages, nevra)
		} else {
			binPackages = append(binPackages, nevra)
		}
	}
	return binPackages, sourcePackages
}

func (req *CvesRequest) getSortedCveIDs(cveDetails CveDetailMap) ([]string, error) {
	cveIDs := req.CveIDs
	if len(cveIDs) == 0 {
		return nil, errors.New("cve_list must contain at least one item")
	}
	cveIDs = utils.TryExpandRegexPattern(cveIDs, cveDetails)
	slices.Sort(cveIDs)
	return cveIDs, nil
}

func filterCveIDs(cveIDs []string, req *CvesRequest, cveDetails CveDetailMap) []string {
	modifiedSince, err := time.Parse(time.RFC3339, req.ModifiedSince)
	if err != nil {
		modifiedSince = time.Time{} // 0001-01-01T00:00:00Z
	}

	publishedSince, err := time.Parse(time.RFC3339, req.PublishedSince)
	if err != nil {
		publishedSince = time.Time{} // 0001-01-01T00:00:00Z
	}

	filteredIDs := make([]string, 0, len(cveIDs))
	for _, cveID := range cveIDs {
		if cveID == "" {
			continue
		}
		cveDetail, found := cveDetails[cveID]
		if !found {
			continue
		}
		if req.RHOnly && cveDetail.Source != "Red Hat" {
			continue
		}
		if req.AreErrataAssociated && len(cveDetail.ErrataIDs) == 0 {
			// FIXME: also check oval
			continue
		}

		if cveDetail.ModifiedDate != nil {
			modifiedDate, err := time.Parse(time.RFC3339, *cveDetail.ModifiedDate)
			if err != nil || modifiedDate.Before(modifiedSince) {
				continue
			}
		}

		if cveDetail.PublishedDate != nil {
			publishedDate, err := time.Parse(time.RFC3339, *cveDetail.PublishedDate)
			if err != nil || publishedDate.Before(publishedSince) {
				continue
			}
		}

		filteredIDs = append(filteredIDs, cveID)
	}
	return filteredIDs
}

func (c *Cache) loadCveProperties(cveIDs []string) CvePropertiesMap {
	cvePropertiesMap := make(CvePropertiesMap, len(cveIDs))
	for _, cveID := range cveIDs {
		cveDetail := c.CveDetail[cveID]
		binPackages, sourcePackages := c.packageIDs2Nevras(cveDetail.PkgIDs)
		cvePropertiesMap[cveID] = CveProperties{
			Synopsis:        cveID,
			Errata:          c.errataIDs2Names(cveDetail.ErrataIDs),
			Packages:        binPackages,
			SourcePackages:  sourcePackages,
			CveDetailCommon: cveDetail.CveDetailCommon,
		}
	}
	return cvePropertiesMap
}

func (req *CvesRequest) cves(c *Cache) (*Cves, error) { // TODO: implement opts
	cveIDs, err := req.getSortedCveIDs(c.CveDetail)
	if err != nil {
		return nil, err
	}

	cveIDs = filterCveIDs(cveIDs, req, c.CveDetail)
	// TODO: add pagination

	// TODO: write tests for everything

	res := Cves{
		Cves:       c.loadCveProperties(cveIDs),
		LastChange: c.DBChange.LastChange,
	}
	return &res, nil
}
