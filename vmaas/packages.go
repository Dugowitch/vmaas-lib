package vmaas

import (
	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type PackageDetails map[string]interface{}

type Packages struct {
	Packages   PackageDetails `json:"package_list"`
	LastChange string         `json:"last_change"`
}

func (c *Cache) nevra2PkgID(nevra utils.Nevra) PkgID {
	nameID, ok := c.Packagename2ID[nevra.Name]
	if !ok {
		return 0
	}
	evrID, ok := c.Evr2ID[nevra.GetEvr()]
	if !ok {
		return 0
	}
	archID, ok := c.Arch2ID[nevra.Arch]
	if !ok {
		return 0
	}

	key := Nevra{
		NameID: nameID,
		EvrID:  evrID,
		ArchID: archID,
	}
	return c.Nevra2PkgID[key]
}

func filterInputPkgs(c *Cache, pkgs []string, req *PackagesRequest) ([]string, map[string]PkgID) {
	isDuplicate := make(map[string]bool, len(pkgs))
	filteredOut := make([]string, 0, len(pkgs))
	filtered := make(map[string]PkgID, len(pkgs))
	for _, pkg := range pkgs {
		if isDuplicate[pkg] {
			continue
		}
		isDuplicate[pkg] = true

		nevra, err := utils.ParseNevra(pkg, false)
		if err != nil {
			filteredOut = append(filteredOut, pkg)
			continue
		}

		pkgID := c.nevra2PkgID(nevra)
		if pkgID == 0 {
			filteredOut = append(filteredOut, pkg)
			continue
		}

		if !req.ThirdParty {
			repoIDs := c.PkgID2RepoIDs[pkgID]
			for _, repoID := range repoIDs {
				repoDetail := c.RepoDetails[repoID]
				if repoDetail.ThirdParty {
					filteredOut = append(filteredOut, pkg)
					continue
				}
			}
		}

		filtered[pkg] = pkgID
	}
	return filteredOut, filtered
}

func (c *Cache) srcPkgID2Pkg(srcPkgID *PkgID) string {
	if srcPkgID == nil {
		return ""
	}

	srcPackageDetail, ok := c.PackageDetails[*srcPkgID]
	if !ok {
		return ""
	}

	return c.pkgDetail2Nevra(srcPackageDetail)
}

func (c *Cache) pkgID2Repos(pkgID PkgID) []RepoDetail {
	repoIDs, ok := c.PkgID2RepoIDs[pkgID]
	if !ok {
		return []RepoDetail{}
	}

	repoDetails := make([]RepoDetail, 0, len(repoIDs))
	for _, repoID := range repoIDs {
		if repoDetail, ok := c.RepoDetails[repoID]; ok {
			repoDetails = append(repoDetails, repoDetail)
		}
	}
	return repoDetails
}

func (c *Cache) pkgID2BuiltBinaryPkgs(pkgID PkgID) []string {
	pkgIDs, ok := c.SrcPkgID2PkgID[pkgID]
	if !ok {
		return []string{}
	}

	pkgs := make([]string, 0, len(pkgIDs))
	for _, pkgID := range pkgIDs {
		if packageDetail, ok := c.PackageDetails[pkgID]; ok {
			pkgs = append(pkgs, c.pkgDetail2Nevra(packageDetail))
		}
	}
	return pkgs
}

func (c *Cache) loadPackageDetails(filteredOut []string, pkgs2pkgIDs map[string]PkgID) PackageDetails {
	pkgDetails := make(PackageDetails, len(pkgs2pkgIDs))
	for pkg, pkgID := range pkgs2pkgIDs {
		pd, ok := c.PackageDetails[pkgID]
		if !ok {
			filteredOut = append(filteredOut, pkg)
			continue
		}

		pkgDetail := PackageDetail{
			Summary:       c.String[pd.SummaryID],
			Description:   c.String[pd.DescriptionID],
			SourcePackage: c.srcPkgID2Pkg(pd.SrcPkgID),
			Repositories:  c.pkgID2Repos(pkgID),
			Packages:      c.pkgID2BuiltBinaryPkgs(pkgID),
		}

		pkgDetails[pkg] = pkgDetail
	}

	for _, pkg := range filteredOut {
		pkgDetails[pkg] = struct{}{}
	}

	return pkgDetails
}

func (req *PackagesRequest) packages(c *Cache) (*Packages, error) { // TODO: implement opts
	pkgs := req.Packages
	if len(pkgs) == 0 {
		return &Packages{}, errors.Wrap(ErrProcessingInput, "'package_list' is a required property")
	}

	filteredOut, pkgs2pkgIDs := filterInputPkgs(c, pkgs, req)

	res := Packages{
		Packages:   c.loadPackageDetails(filteredOut, pkgs2pkgIDs),
		LastChange: c.DBChange.LastChange,
	}
	return &res, nil
}
