import clsx from "clsx";
import { Toast } from "../types";

type ToastStackProps = {
  toastList: Toast[];
};

export function ToastStack({ toastList }: ToastStackProps) {
  if (toastList.length === 0) return null;

  return (
    <div className="pointer-events-none fixed inset-0 z-[60] flex items-start justify-end px-4 py-6">
      <div className="flex flex-col gap-3">
        {toastList.map((toast) => (
          <div
            key={toast.id}
            className={clsx(
              "pointer-events-auto rounded-2xl border px-4 py-3 text-sm shadow-2xl backdrop-blur",
              toast.tone === "success"
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-100"
                : "border-rose-500/40 bg-rose-500/10 text-rose-100",
            )}
          >
            <p className="font-semibold">{toast.title}</p>
            <p className="text-xs opacity-80">{toast.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}


