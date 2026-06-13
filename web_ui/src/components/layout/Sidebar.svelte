<script lang="ts">
  import Icon from "../Icon.svelte";
  import logoUrl from "../../assets/images/forensia-logo.svg";
  import { searchQuery } from "../../lib/stores";

  export let collapsed = false;
  export let view = "dashboard";
  export let onToggle: () => void = () => {};
  export let onNavigate: (item: { id: string; view: string; anchor: string | null }) => void = () => {};

  type NavItem = { id: string; label: string; icon: string; view: string; anchor: string | null };

  // MAIN items scroll to anchored sections on the dashboard; SYSTEM switches view.
  const main: NavItem[] = [
    { id: "dashboard", label: "Dashboard", icon: "dashboard", view: "dashboard", anchor: "#top" },
    { id: "timeline", label: "Activity", icon: "activity", view: "dashboard", anchor: "#timeline" },
    { id: "report", label: "Report", icon: "report", view: "dashboard", anchor: "#report" },
    { id: "hypotheses", label: "Hypotheses", icon: "hypotheses", view: "dashboard", anchor: "#hypotheses" },
    { id: "findings", label: "Findings", icon: "findings", view: "dashboard", anchor: "#details" },
    { id: "gaps", label: "Open Gaps", icon: "gaps", view: "dashboard", anchor: "#gaps" }
  ];
  const system: NavItem[] = [
    { id: "settings", label: "Settings", icon: "settings", view: "settings", anchor: null }
  ];

  let active = "dashboard";

  function select(item: NavItem): void {
    active = item.id;
    onNavigate(item);
  }

  // Keep the highlight on Settings whenever the settings view is open, even if
  // the user scrolls the dashboard underneath is irrelevant here.
  $: if (view === "settings") active = "settings";
</script>

<aside
  class={`sticky top-0 z-20 flex h-screen shrink-0 flex-col border-r border-mocha-surface1 bg-semantic-bg transition-[width] duration-200 ${collapsed ? "w-16" : "w-60"}`}
>
  <!-- Brand -->
  <div class={`flex shrink-0 items-center border-b border-mocha-surface1 ${collapsed ? "justify-center px-0 py-5" : "px-5 py-5"}`}>
    {#if collapsed}
      <div class="grid h-9 w-9 place-items-center rounded-lg bg-semantic-accent/15 text-lg font-bold text-semantic-accent">F</div>
    {:else}
      <div class="flex min-w-0 flex-col gap-1.5">
        <img src={logoUrl} alt="FORENSIA" class="h-[24px] w-auto brightness-0 invert" />
        <div class="text-[10px] uppercase tracking-wider text-semantic-fg-faint">Your Offline AI Forensic Analyst</div>
      </div>
    {/if}
  </div>

  <!-- Search -->
  {#if !collapsed}
    <div class="shrink-0 border-b border-mocha-surface1 px-3 py-3">
      <div class="relative">
        <span class="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-semantic-fg-faint">
          <Icon name="search" size={15} />
        </span>
        <input
          type="search"
          bind:value={$searchQuery}
          placeholder="Search findings…"
          class="w-full rounded-lg border border-mocha-surface1 bg-semantic-bg-inset/60 py-1.5 pl-8 pr-2.5 text-sm text-semantic-fg placeholder:text-semantic-fg-faint focus:border-semantic-accent/50 focus:outline-none focus:ring-1 focus:ring-semantic-accent/30"
        />
      </div>
    </div>
  {/if}

  <!-- Nav -->
  <nav class="flex-1 overflow-y-auto px-2 py-4">
    {#if !collapsed}
      <div class="px-2 pb-2 text-[10px] font-semibold uppercase tracking-wider text-semantic-fg-faint">Main</div>
    {/if}
    <ul class="flex flex-col gap-1">
      {#each main as item}
        <li>
          <button
            type="button"
            title={item.label}
            on:click={() => select(item)}
            class={`flex w-full items-center rounded-lg text-sm font-medium transition-colors ${collapsed ? "justify-center px-0 py-2.5" : "gap-3 px-3 py-2"} ${
              active === item.id
                ? "bg-semantic-accent/10 text-semantic-accent"
                : "text-semantic-fg-muted hover:bg-white/5 hover:text-semantic-fg"
            }`}
          >
            <Icon name={item.icon} size={18} />
            {#if !collapsed}<span class="truncate">{item.label}</span>{/if}
          </button>
        </li>
      {/each}
    </ul>

    {#if !collapsed}
      <div class="px-2 pb-2 pt-5 text-[10px] font-semibold uppercase tracking-wider text-semantic-fg-faint">System</div>
    {:else}
      <div class="my-3 h-px bg-mocha-surface1"></div>
    {/if}
    <ul class="flex flex-col gap-1">
      {#each system as item}
        <li>
          <button
            type="button"
            title={item.label}
            on:click={() => select(item)}
            class={`flex w-full items-center rounded-lg text-sm font-medium transition-colors ${collapsed ? "justify-center px-0 py-2.5" : "gap-3 px-3 py-2"} ${
              active === item.id
                ? "bg-semantic-accent/10 text-semantic-accent"
                : "text-semantic-fg-muted hover:bg-white/5 hover:text-semantic-fg"
            }`}
          >
            <Icon name={item.icon} size={18} />
            {#if !collapsed}<span class="truncate">{item.label}</span>{/if}
          </button>
        </li>
      {/each}
    </ul>
  </nav>

  <!-- Collapse toggle -->
  <div class="shrink-0 border-t border-mocha-surface1 p-2">
    <button
      type="button"
      on:click={onToggle}
      title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      class={`flex w-full items-center rounded-lg text-sm font-medium text-semantic-fg-muted transition-colors hover:bg-white/5 hover:text-semantic-fg ${collapsed ? "justify-center px-0 py-2.5" : "gap-3 px-3 py-2"}`}
    >
      <Icon name={collapsed ? "expand" : "collapse"} size={18} />
      {#if !collapsed}<span>Collapse</span>{/if}
    </button>
  </div>
</aside>
