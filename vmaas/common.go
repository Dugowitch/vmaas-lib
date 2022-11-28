package vmaas

import (
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

const SecurityErrataType = "security"

type ProcessedRequest struct {
	Updates         *Updates
	Packages        map[string]utils.Nevra
	OriginalRequest *Request
}

func (r *ProcessedRequest) evaluateRepositories(c *Cache) *Updates {
	if len(r.Packages) == 0 {
		return r.Updates
	}

	repoIDs := getRepoIDs(c, r.Updates.RepoList)
	utils.Log("repoIDs", repoIDs).Trace("processRequest - repoIDs unfiltered")
	repoIDs = filterReposByReleasever(c, r.Updates.Releasever, repoIDs)

	// Get list of valid repository IDs based on input parameters
	repoIDs = filterReposByBasearch(c, r.Updates.BaseArch, repoIDs)

	moduleIDs := getModules(c, r.Updates.ModuleList)

	utils.Log("moduleIDs", moduleIDs, "repoIDs", repoIDs).Trace("processRequest")
	// Process updated packages, errata and fill the response
	updateList := processUpdates(c, r.Updates.UpdateList, r.Packages, repoIDs, moduleIDs, r.OriginalRequest)
	r.Updates.UpdateList = updateList

	return r.Updates
}

// This method is looking for updates of a package, including name of package to update to,
// associated erratum and repository this erratum is from.
func (r *Request) processRequest(c *Cache) (*ProcessedRequest, error) {
	lastChanged, err := time.Parse(time.RFC3339, c.DBChange.LastChange)
	if err != nil {
		return nil, errors.Wrap(err, "parsing lastChanged")
	}

	pkgsToProcess, updateList := processInputPackages(c, r)
	updates := Updates{
		UpdateList: updateList,
		LastChange: lastChanged,
		BaseArch:   r.Basearch,
		Releasever: r.Releasever,
		RepoList:   r.Repos,
		ModuleList: r.Modules,
	}
	processed := ProcessedRequest{Updates: &updates, Packages: pkgsToProcess, OriginalRequest: r}
	return &processed, nil
}

// Parse input NEVRAs and filter out unknown (or without updates) package names
func processInputPackages(c *Cache, request *Request) (map[string]utils.Nevra, UpdateList) {
	pkgsToProcess := filterPkgList(request.Packages, request.LatestOnly)
	utils.Log("pkgsToProcess", pkgsToProcess).Trace("processInputPackages")
	filteredPkgsToProcess := make(map[string]utils.Nevra)
	updateList := make(UpdateList)
	for _, pkg := range pkgsToProcess {
		updateList[pkg] = UpdateDetail{}
		nevra, err := utils.ParseNevra(pkg)
		if err != nil {
			utils.Log("nevra", pkg).Warn("Cannot parse")
			continue
		}
		if pkgID, ok := c.Packagename2ID[nevra.Name]; ok {
			for idx := range c.UpdatesIndex {
				if pkgID == idx {
					filteredPkgsToProcess[pkg] = nevra
					break
				}
			}
		}
	}
	utils.Log("filteredPkgsToProcess", filteredPkgsToProcess, "updateList", updateList).Trace("processInputPackages")
	return filteredPkgsToProcess, updateList
}

func processUpdates(c *Cache, updateList UpdateList, packages map[string]utils.Nevra,
	repoIDs []RepoID, moduleIDs map[int]bool, r *Request,
) UpdateList {
	for pkg, nevra := range packages {
		updateList[pkg] = processPackagesUpdates(c, nevra, repoIDs, moduleIDs, r)
	}
	return updateList
}

func processPackagesUpdates(c *Cache, nevra utils.Nevra, repoIDs []RepoID, moduleIDs map[int]bool, r *Request,
) UpdateDetail {
	updateDetail := UpdateDetail{}
	nevraIDs := extractNevraIDs(c, &nevra)

	var updatePkgIDs []PkgID
	var validReleasevers map[string]bool
	switch {
	case len(nevraIDs.EvrIDs) > 0:
		// nevraUpdates
		updatePkgIDs, validReleasevers = nevraUpdates(c, &nevraIDs)
	case r.Optimistic:
		updatePkgIDs = optimisticUpdates(c, &nevraIDs, &nevra)
		validReleasevers = nil
	default:
		return UpdateDetail{}
	}

	utils.Log("updatePkgIDs", updatePkgIDs, "validReleasevers", validReleasevers).Trace("processPackagesUpdates")

	for _, u := range updatePkgIDs {
		updates := pkgUpdates(c, u, nevraIDs.ArchID, r.SecurityOnly, moduleIDs,
			repoIDs, validReleasevers, r.ThirdParty)
		updateDetail.AvailableUpdates = append(updateDetail.AvailableUpdates, updates...)
	}

	utils.Log("updateDetail", updateDetail).Trace("processPackagesUpdates")
	return updateDetail
}

func pkgUpdates(c *Cache, pkgID PkgID, archID ArchID, securityOnly bool, modules map[int]bool,
	repoIDs []RepoID, releasevers map[string]bool, thirdparty bool,
) []Update {
	if archID == 0 {
		return nil
	}

	// Filter out packages without errata
	if _, ok := c.PkgID2ErrataIDs[pkgID]; !ok {
		utils.Log().Trace("pkgUpdates - no errata")
		return nil
	}

	// Filter arch compatibility
	updatedNevraArchID := c.PackageDetails[pkgID].ArchID
	if updatedNevraArchID != archID {
		if _, ok := c.ArchCompat[archID]; !ok {
			utils.Log().Trace("pkgUpdates - no compatible arch")
			return nil
		}
	}

	errataIDs := c.PkgID2ErrataIDs[pkgID]
	nevra := buildNevra(c, pkgID)
	updates := []Update{}
	utils.Log("errataIDs", errataIDs, "nevra", nevra).Trace("pkgUpdates")
	for _, eid := range errataIDs {
		errataUpdates := pkgErrataUpdates(c, pkgID, eid, modules, repoIDs,
			releasevers, nevra, securityOnly, thirdparty)
		updates = append(updates, errataUpdates...)
	}
	return updates
}

func pkgErrataUpdates(c *Cache, pkgID PkgID, erratumID ErrataID, modules map[int]bool,
	repoIDs []RepoID, releasevers map[string]bool, nevra utils.Nevra, securityOnly, thirdparty bool,
) []Update {
	erratumName := c.ErrataID2Name[erratumID]
	erratumDetail := c.ErrataDetail[erratumName]

	// Filter out non-security updates
	if filterNonSecurity(erratumDetail, securityOnly) {
		utils.Log().Trace("pkgErrataUpdate - non security")
		return nil
	}

	// If we don't want third party content, and current advisory is third party, skip it
	if !thirdparty && erratumDetail.ThirdParty {
		utils.Log().Trace("pkgErrataUpdate - 3rd party")
		return nil
	}

	pkgErrata := PkgErrata{
		PkgID:    int(pkgID),
		ErrataID: int(erratumID),
	}
	errataModules := c.PkgErrata2Module[pkgErrata]
	utils.Log("errataModules", errataModules, "pkgErrata", pkgErrata, "modules", modules).Trace("pkgErrataUpdate")
	// return nil if errataModules and modules intersection is empty
	intersects := false
	for _, em := range errataModules {
		if _, ok := modules[em]; ok {
			// at least 1 item in intersection
			intersects = true
			break
		}
	}
	if len(errataModules) > 0 && intersects == false {
		return nil
	}

	repos := filterRepositories(c, pkgID, erratumID, repoIDs, releasevers)
	utils.Log("repos", repos, "pkgErrata", pkgErrata, "errataModules", errataModules).Trace(
		"pkgErrataUpdates - filter repositories")
	updates := make([]Update, 0, len(repos))
	for _, r := range repos {
		details := c.RepoDetails[r]
		updates = append(updates, Update{
			Package:    nevra.String(),
			Erratum:    erratumName,
			Repository: details.Label,
			Basearch:   details.BaseArch,
			Releasever: details.ReleaseVer,
		})
	}
	return updates
}

// Decide whether the errata should be filtered base on 'security only' rule
func filterNonSecurity(errataDetail ErrataDetail, securityOnly bool) bool {
	if !securityOnly {
		return false
	}
	isSecurity := errataDetail.Type == SecurityErrataType || len(errataDetail.CVEs) > 0
	return !isSecurity
}

func filterRepositories(c *Cache, pkgID PkgID, erratumID ErrataID, repoIDs []RepoID,
	releasevers map[string]bool,
) []RepoID {
	errataRepoIDs := make(map[RepoID]bool)
	errataRepos := c.ErrataID2RepoIDs[erratumID]
	for _, er := range errataRepos {
		errataRepoIDs[er] = true
	}

	pkgRepos := c.PkgID2RepoIDs[pkgID]
	utils.Log("available_repo_ids", repoIDs, "c.PkgID2RepoIDs[pkgID]", pkgRepos,
		"errata_repo_ids", errataRepoIDs).Trace("filterRepositories")

	result := make([]RepoID, 0, len(repoIDs))
	pkgRepoIDs := make(map[RepoID]bool)
	for _, rid := range pkgRepos {
		pkgRepoIDs[rid] = true
	}

	for _, rid := range repoIDs {
		if pkgRepoIDs[rid] && errataRepoIDs[rid] {
			if isRepoValid(c, rid, releasevers) {
				result = append(result, rid)
			}
		}
	}
	return result
}

func isRepoValid(c *Cache, repoID RepoID, releasevers map[string]bool) bool {
	if len(releasevers) == 0 {
		return true
	}
	repoDetail := c.RepoDetails[repoID]
	return repoDetail.ReleaseVer != nil && releasevers[*repoDetail.ReleaseVer]
}

func buildNevra(c *Cache, pkgID PkgID) utils.Nevra {
	pkgDetail := c.PackageDetails[pkgID]
	name := c.ID2Packagename[pkgDetail.NameID]
	evr := c.ID2Evr[pkgDetail.EvrID]
	arch := c.ID2Arch[pkgDetail.ArchID]
	nevra := utils.Nevra{
		Name:    name,
		Epoch:   evr.Epoch,
		Version: evr.Version,
		Release: evr.Release,
		Arch:    arch,
	}
	return nevra
}

func optimisticUpdates(c *Cache, nevraIDs *NevraIDs, nevra *utils.Nevra) []PkgID {
	updatePkgIDs := c.Updates[nevraIDs.NameID]
	updateIDx := 0
	for i := len(updatePkgIDs) - 1; i > 0; i-- {
		// go from the end of list because we expect most system is up2date
		// therefore we will test just a few pkgs at the end
		updatePkg := c.PackageDetails[updatePkgIDs[i]]
		updateEvr := c.ID2Evr[updatePkg.EvrID]
		// create NEVRA type to compare rpm version
		updateNevra := utils.Nevra{
			Name:    nevra.Name,
			Epoch:   updateEvr.Epoch,
			Version: updateEvr.Version,
			Release: updateEvr.Release,
			Arch:    nevra.Arch,
		}
		if updateNevra.EVRACmp(nevra) <= 0 {
			updateIDx = i
			break
		}
	}
	filteredUpdates := updatePkgIDs[updateIDx+1:]
	return filteredUpdates
}

func nevraUpdates(c *Cache, n *NevraIDs) ([]PkgID, map[string]bool) {
	currentNevraPkgID := nevraPkgID(c, n)
	// Package with given NEVRA not found in cache/DB
	if currentNevraPkgID == 0 {
		return nil, nil
	}

	// No updates found for given NEVRA
	lastVersionPkgID := c.Updates[n.NameID][len(c.Updates[n.NameID])-1]
	if lastVersionPkgID == currentNevraPkgID {
		return nil, nil
	}

	// Get candidate package IDs
	updatePkgIDs := c.Updates[n.NameID][n.EvrIDs[len(n.EvrIDs)-1]+1:]

	// Get associated product IDs
	validReleasevers := pkgReleasevers(c, currentNevraPkgID)
	return updatePkgIDs, validReleasevers
}

func pkgReleasevers(c *Cache, pkgID PkgID) map[string]bool {
	repoIDs := c.PkgID2RepoIDs[pkgID]
	releasevers := make(map[string]bool)
	for _, rid := range repoIDs {
		relVer := c.RepoDetails[rid].ReleaseVer
		if relVer != nil {
			releasevers[*relVer] = true
		}
	}
	return releasevers
}

func nevraPkgID(c *Cache, n *NevraIDs) PkgID {
	var nPkgID PkgID
	for _, eid := range n.EvrIDs {
		pkgID := c.Updates[n.NameID][eid]
		nevraArchID := c.PackageDetails[pkgID].ArchID
		if nevraArchID == n.ArchID {
			nPkgID = pkgID
			break
		}
	}
	return nPkgID
}

func extractNevraIDs(c *Cache, nevra *utils.Nevra) NevraIDs {
	nameID := c.Packagename2ID[nevra.Name]
	evr := utils.Evr{
		Epoch:   nevra.Epoch,
		Version: nevra.Version,
		Release: nevra.Release,
	}
	evrID := c.Evr2ID[evr]
	archID := c.Arch2ID[nevra.Arch]
	currentEvrIndexes := c.UpdatesIndex[nameID][evrID]
	return NevraIDs{
		NameID: nameID,
		EvrIDs: currentEvrIndexes,
		ArchID: archID,
	}
}

// Filter packages with latest NEVRA
func filterPkgList(pkgs []string, latestOnly bool) []string {
	if !latestOnly {
		return pkgs
	}

	latestPkgs := make(map[NameArch]NevraString, len(pkgs))
	filtered := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		nevra, err := utils.ParseNevra(pkg)
		if err != nil {
			utils.Log("nevra", pkg).Warn("Cannot parse")
			continue
		}
		nameArch := NameArch{Name: nevra.Name, Arch: nevra.Arch}
		utils.Log("nameArch", nameArch, "nevra", nevra).Trace("filterPkgList")
		if latestPkg, ok := latestPkgs[nameArch]; ok {
			if nevra.EVRCmp(&latestPkg.Nevra) < 1 {
				// nevra <= latestPkg
				continue
			}
		}
		latestPkgs[nameArch] = NevraString{nevra, pkg}
	}
	for _, v := range latestPkgs {
		filtered = append(filtered, v.Pkg)
	}
	return filtered
}

func getRepoIDs(c *Cache, repos []string) []RepoID {
	tmp := make(map[RepoID]bool, len(repos))
	repoIDs := make([]RepoID, 0, len(repos))
	if len(repos) == 0 {
		for k, _ := range c.RepoDetails {
			repoIDs = append(repoIDs, k)
		}
	}
	for _, label := range repos {
		repoIDsCache := c.RepoLabel2IDs[label]
		for _, r := range repoIDsCache {
			if !tmp[r] {
				repoIDs = append(repoIDs, r)
				tmp[r] = true
			}
		}
	}
	return repoIDs
}

func filterReposByReleasever(c *Cache, releasever *string, repoIDs []RepoID) []RepoID {
	if releasever != nil {
		repos := make([]RepoID, 0, len(repoIDs))
		for _, oid := range repoIDs {
			detailReleasever := c.RepoDetails[oid].ReleaseVer
			if (detailReleasever == nil && strings.Contains(c.RepoDetails[oid].URL, *releasever)) ||
				(detailReleasever != nil && *detailReleasever == *releasever) {
				repos = append(repos, oid)
			}
		}
		repoIDs = repos
	}
	return repoIDs
}

func filterReposByBasearch(c *Cache, basearch *string, repoIDs []RepoID) []RepoID {
	if basearch != nil {
		repos := make([]RepoID, 0, len(repoIDs))
		for _, oid := range repoIDs {
			detailBasearch := c.RepoDetails[oid].BaseArch
			if (detailBasearch == nil && strings.Contains(c.RepoDetails[oid].URL, *basearch)) ||
				(detailBasearch != nil && *detailBasearch == *basearch) {
				repos = append(repos, oid)
			}
		}
		repoIDs = repos
	}
	return repoIDs
}

func getModules(c *Cache, modules []ModuleStream) map[int]bool {
	moduleIDs := make(map[int]bool, len(modules))
	for _, m := range modules {
		if mIDs, ok := c.Module2IDs[m]; ok {
			for _, id := range mIDs {
				moduleIDs[id] = true
			}
		}
	}
	// filter out streams without satisfied requires
	filteredIDs := make(map[int]bool, len(moduleIDs))
	for m := range moduleIDs {
		requires := c.ModuleRequires[m]
		issubset := true
		for _, r := range requires {
			if !moduleIDs[r] {
				issubset = false
			}
		}
		if issubset {
			filteredIDs[m] = true
		}
	}
	return filteredIDs
}

func cveMapKeys(cves map[string]VulnerabilityDetail) []Vulnerability {
	keys := make([]Vulnerability, 0, len(cves))
	for k := range cves {
		keys = append(keys, Vulnerability(k))
	}
	return keys
}

func cveMapValues(cves map[string]VulnerabilityDetail) []VulnerabilityDetail {
	vals := make([]VulnerabilityDetail, 0, len(cves))
	for _, v := range cves {
		vals = append(vals, v)
	}
	return vals
}