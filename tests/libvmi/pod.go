package libvmi

import (
	"fmt"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "kubevirt.io/client-go/api/v1"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/kubevirt/pkg/controller"
	testerrors "kubevirt.io/kubevirt/tests/errors"
)

func GetPodByVirtualMachineInstance(vmi *v1.VirtualMachineInstance, namespace string) *k8sv1.Pod {
	virtCli, err := kubecli.GetKubevirtClient()
	testerrors.PanicOnError(err)

	pods, err := virtCli.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	testerrors.PanicOnError(err)

	var controlledPod *k8sv1.Pod
	for _, pod := range pods.Items {
		if controller.IsControlledBy(&pod, vmi) {
			controlledPod = &pod
			break
		}
	}

	if controlledPod == nil {
		testerrors.PanicOnError(fmt.Errorf("no controlled pod was found for VMI"))
	}

	return controlledPod
}
