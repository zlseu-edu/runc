package fs

import (
	"fmt"
	"path/filepath"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
)

var (
	supportedSubsystems = supportedSubsystemSet{
		"blkio",
		"memory",
	}
)

type supportedSubsystemSet []string

type UnifiedGroup struct {
}

var errSubsystemDoesNotSupport = fmt.Errorf("cgroup v2: system not support")

func (s *UnifiedGroup) Name() string {
	return "unified"
}

func (s *UnifiedGroup) Apply(d *cgroupData) error {
	_, err := d.join("unified")
	if err != nil && !cgroups.IsNotFound(err) {
		return err
	}
	return nil
}

func (s *UnifiedGroup) Set(path string, cgroup *configs.Cgroup) error {
	for _, sys := range supportedSubsystems {
		// if not find subsystem in cgroup v1, so in v2.
		if _, err := cgroups.FindCgroupMountpoint(sys); err != nil {
			switch sys {
			case "blkio":
				if err := setBlkio(path, cgroup); err != nil {
					return err
				}
			case "memory":
				if err := setMemory(path, cgroup); err != nil {
					return err
				}
			case "cpu":
				if err := setCpu(path, cgroup); err != nil {
					return err
				}
			default:
				return errSubsystemDoesNotSupport
			}
		}
	}
	return nil
}

func setBlkio(path string, cgroup *configs.Cgroup) error {

	if err := prepareController("+io"); err != nil {
		return err
	}

	for _, wd := range cgroup.Resources.BlkioWeightDevice {
		if err := writeFile(path, "io.weight", wd.WeightString()); err != nil {
			return err
		}
		if err := writeFile(path, "io.weight", wd.LeafWeightString()); err != nil {
			return err
		}
	}
	for _, td := range cgroup.Resources.BlkioThrottleReadBpsDevice {
		if err := writeFile(path, "io.max", td.String2("rbps")); err != nil {
			return err
		}
	}
	for _, td := range cgroup.Resources.BlkioThrottleWriteBpsDevice {
		if err := writeFile(path, "io.max", td.String2("wbps")); err != nil {
			return err
		}
	}
	for _, td := range cgroup.Resources.BlkioThrottleReadIOPSDevice {
		if err := writeFile(path, "io.max", td.String2("riops")); err != nil {
			return err
		}
	}
	for _, td := range cgroup.Resources.BlkioThrottleWriteIOPSDevice {
		if err := writeFile(path, "io.max", td.String2("wiops")); err != nil {
			return err
		}
	}

	return nil
}

func setMemory(path string, cgroup *configs.Cgroup) error {

	if err := prepareController("+memory"); err != nil {
		return err
	}
	return nil
}

func setCpu(path string, cgroup *configs.Cgroup) error {

	if err := prepareController("+cpu"); err != nil {
		return err
	}
	return nil
}

func prepareController(controller string) error {
	rootPath, err := cgroups.GetOwnCgroupPath("unified")
	if err != nil {
		return errSubsystemDoesNotSupport
	}

	paths := make([]string, 0)
	for cgroups.PathExists(filepath.Join(rootPath, "cgroup.subtree_control")) {
		paths = append(paths, rootPath)
		rootPath = filepath.Dir(rootPath)
	}

	len := len(paths)
	for index := len - 1; index > -1; index-- {
		if err := writeFile(paths[index], "cgroup.subtree_control", controller); err != nil {
			return err
		}
	}

	return nil
}

func (s *UnifiedGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}

func (s *UnifiedGroup) Remove(d *cgroupData) error {
	return removePath(d.path("unified"))
}
