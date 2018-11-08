package fs

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
)

var (
	supportedSubsystems = supportedSubsystemSet{
		"blkio",
		"memory",
		"cpu",
		"pids",
		"devices",
		"perf_event",
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
			case "pids":
				if err := setPids(path, cgroup); err != nil {
					return err
				}
			case "devices":
				if err := setDevices(path, cgroup); err != nil {
					return err
				}
			case "perf_event":
				if err := setPerf_event(path, cgroup); err != nil {
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

func setKernelMemory2(path string, kernelMemoryLimit int64) error {
	return nil
}

func setMemoryAndSwap2(path string, cgroup *configs.Cgroup) error {
	if cgroup.Resources.Memory == -1 {
		cgroup.Resources.MemorySwap = -1
	}

	if cgroup.Resources.Memory != 0 && cgroup.Resources.MemorySwap != 0 {
		if err := writeFile(path, "memory.max", strconv.FormatInt(cgroup.Resources.Memory, 10)); err != nil {
			return err
		}
		if err := writeFile(path, "memory.swap.max", strconv.FormatInt(cgroup.Resources.MemorySwap, 10)); err != nil {
			return err
		}
	}
	return nil
}

func setMemory(path string, cgroup *configs.Cgroup) error {

	if err := prepareController("+memory"); err != nil {
		return err
	}

	if err := setMemoryAndSwap2(path, cgroup); err != nil {
		return err
	}

	if cgroup.Resources.KernelMemory != 0 {
		if err := setKernelMemory2(path, cgroup.Resources.KernelMemory); err != nil {
			return err
		}
	}

	return nil
}

func setCpu(path string, cgroup *configs.Cgroup) error {

	if err := prepareController("+cpu"); err != nil {
		return err
	}

	if cgroup.Resources.CpuShares != 0 {
		if err := writeFile(path, "cpu.weight", strconv.FormatUint(cgroup.Resources.CpuShares, 10)); err != nil {
			return err
		}
	}

	// cgroup v2, cpu controller. "$max $period"
	if cgroup.Resources.CpuQuota != 0 {
		quota := strconv.FormatInt(cgroup.Resources.CpuQuota, 10)
		period := "100000"
		if cgroup.Resources.CpuPeriod != 0 {
			period = strconv.FormatUint(cgroup.Resources.CpuPeriod, 10)
		}
		result := fmt.Sprintf("%s %s", quota, period)
		if err := writeFile(path, "cpu.max", result); err != nil {
			return err
		}
	}

	return nil
}

func setPids(path string, cgroup *configs.Cgroup) error {

	if err := prepareController("+pids"); err != nil {
		return err
	}

	if cgroup.Resources.PidsLimit != 0 {
		// "max" is the fallback value.
		limit := "max"

		if cgroup.Resources.PidsLimit > 0 {
			limit = strconv.FormatInt(cgroup.Resources.PidsLimit, 10)
		}

		if err := writeFile(path, "pids.max", limit); err != nil {
			return err
		}
	}
	return nil
}

func setDevices(path string, cgroup *configs.Cgroup) error {

	if err := prepareController("+devices"); err != nil {
		return err
	}

	// TODO: example in tools/testing/selftests/bpf/dev_cgroup.c

	return nil
}

func setPerf_event(path string, cgroup *configs.Cgroup) error {

	if err := prepareController("+perf_event"); err != nil {
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
	for _, sys := range supportedSubsystems {
		// if not find subsystem in cgroup v1, so in v2.
		if _, err := cgroups.FindCgroupMountpoint(sys); err != nil {
			switch sys {
			case "blkio":
				if err := getBlkioStats(path, stats); err != nil {
					return err
				}
			case "memory":
				if err := getMemoryStats(path, stats); err != nil {
					return err
				}
			case "cpu":
				if err := getCpuStats(path, stats); err != nil {
					return err
				}
			case "pids":
				if err := getPidsStats(path, stats); err != nil {
					return err
				}
			case "devices":
				if err := getDevicesStats(path, stats); err != nil {
					return err
				}
			case "perf_event":
				if err := getPerf_eventStats(path, stats); err != nil {
					return err
				}
			default:
				return errSubsystemDoesNotSupport
			}
		}
	}
	return nil
}

func getBlkioStats(path string, stats *cgroups.Stats) error {
	return nil
}

func getMemoryStats(path string, stats *cgroups.Stats) error {
	return nil
}

func getCpuStats(path string, stats *cgroups.Stats) error {
	f, err := os.Open(filepath.Join(path, "cpu.stat"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := getCgroupParamKeyValue(sc.Text())
		if err != nil {
			return err
		}
		switch t {
		case "nr_periods":
			stats.CpuStats.ThrottlingData.Periods = v

		case "nr_throttled":
			stats.CpuStats.ThrottlingData.ThrottledPeriods = v

		case "throttled_time":
			stats.CpuStats.ThrottlingData.ThrottledTime = v
		}
	}
	return nil
}

func getPidsStats(path string, stats *cgroups.Stats) error {
	return nil
}

func getDevicesStats(path string, stats *cgroups.Stats) error {
	return nil
}

func getPerf_eventStats(path string, stats *cgroups.Stats) error {
	return nil
}

func (s *UnifiedGroup) Remove(d *cgroupData) error {
	return removePath(d.path("unified"))
}
