<script lang="ts">
  export let title = "アクティブな仮説はありません";
  export let status = "待機";
  export let summary = "";
</script>

<section class="panel min-w-0 p-4">
  <div class="mb-3 flex items-center justify-between gap-2">
    <h3 class="panel-title">Current Hypothesis</h3>
    <span class="chip">{status}</span>
  </div>
  <h4 class="truncate text-sm font-semibold text-mocha-text">{title}</h4>
  <p class="mt-2 line-clamp-4 min-h-[6rem] text-sm text-mocha-subtext1">{summary}</p>
</section>
