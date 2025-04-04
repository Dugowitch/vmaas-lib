package vmaas

import (
	"slices"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type ErrataDetails map[string]ErratumDetail

type Errata struct {
	ErrataList ErrataDetails `json:"errata_list"`
	Type       TypeT         `json:"type,omitempty"`
	Severity   SeverityT     `json:"severity,omitempty"`
	LastChange string        `json:"last_change"`
	utils.PaginationDetails
}

func (req *ErrataRequest) getSortedErrata(c *Cache) ([]string, error) {
	if len(req.Errata) == 0 {
		return nil, errors.Wrap(ErrProcessingInput, "'errata_list' is a required property")
	}

	errata, err := utils.TryExpandRegexPattern(req.Errata, c.ErratumDetails)
	if err != nil {
		return nil, errors.Wrap(ErrProcessingInput, "invalid regex pattern")
	}
	slices.Sort(errata)
	return errata, nil
}

func filterInputErrata(c *Cache, errata []string, req *ErrataRequest) []string {
	isDuplicate := make(map[string]bool, len(errata))
	filteredErrata := make([]string, 0, len(errata))
	for _, erratum := range errata {
		if erratum == "" || isDuplicate[erratum] {
			continue
		}
		erratumDetail, found := c.ErratumDetails[erratum]
		if !found {
			continue
		}

		if !req.ThirdParty && erratumDetail.ThirdParty {
			continue
		}

		if req.ModifiedSince != nil {
			if erratumDetail.Issued != nil && erratumDetail.Issued.Before(*req.ModifiedSince) {
				continue
			}
			if erratumDetail.Updated != nil && erratumDetail.Updated.Before(*req.ModifiedSince) {
				continue
			}
		}

		if req.Type != nil && !slices.Contains(req.Type, erratumDetail.Type) {
			continue
		}

		if req.Severity != nil && !req.Severity.contains(erratumDetail.Severity) {
			continue
		}

		filteredErrata = append(filteredErrata, erratum)
		isDuplicate[erratum] = true
	}
	return filteredErrata
}

func (c *Cache) erratumID2Releasevers(erratumID ErratumID) []string {
	erratumRepos := c.ErratumID2RepoIDs[erratumID]
	releaseVers := make([]string, 0, len(erratumRepos))
	isDuplicate := make(map[string]bool, len(erratumRepos))
	for repoID := range erratumRepos {
		repoDetail := c.RepoDetails[repoID]
		releaseVer := repoDetail.Releasever
		if releaseVer != "" && !isDuplicate[releaseVer] {
			releaseVers = append(releaseVers, releaseVer)
			isDuplicate[releaseVer] = true
		}
	}
	return releaseVers
}

func (c *Cache) loadErrataDetails(errata []string) ErrataDetails {
	errataDetails := make(ErrataDetails, len(errata))
	for _, erratum := range errata {
		erratumDetail := c.ErratumDetails[erratum]
		binPackages, sourcePackages := c.packageIDs2Nevras(erratumDetail.PkgIDs)
		erratumDetail.PackageList = binPackages
		erratumDetail.SourcePackageList = sourcePackages
		erratumDetail.ReleaseVersions = c.erratumID2Releasevers(erratumDetail.ID)
		if erratumDetail.CVEs == nil {
			erratumDetail.CVEs = []string{}
		}
		if erratumDetail.Bugzillas == nil {
			erratumDetail.Bugzillas = []string{}
		}
		if erratumDetail.Refs == nil {
			erratumDetail.Refs = []string{}
		}
		if erratumDetail.Modules == nil {
			erratumDetail.Modules = []Module{}
		}
		errataDetails[erratum] = erratumDetail
	}
	return errataDetails
}

func (req *ErrataRequest) errata(c *Cache) (*Errata, error) { // TODO: implement opts
	errata, err := req.getSortedErrata(c)
	if err != nil {
		return &Errata{}, err
	}

	errata = filterInputErrata(c, errata, req)
	errata, paginationDetails := utils.Paginate(errata, req.PageNumber, req.PageSize)

	res := Errata{
		ErrataList:        c.loadErrataDetails(errata),
		Type:              req.Type,
		Severity:          req.Severity,
		LastChange:        c.DBChange.LastChange,
		PaginationDetails: paginationDetails,
	}
	return &res, nil
}
