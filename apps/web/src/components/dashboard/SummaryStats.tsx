'use client';

import React, { useEffect, useMemo, useState } from 'react';
import {
  CURRENCY_OPTIONS,
  CurrencyCode,
  FALLBACK_XLM_RATES,
  convertXlmAmount,
  fetchXlmFiatRates,
  formatCurrencyAmount,
} from './currency';

interface SummaryStatsProps {
  totalPaymentsCount: number;
  totalVolumeXLM: number;
  activeWalletsCount: number;
  rates?: Partial<Record<CurrencyCode, number>>;
}

export const SummaryStats: React.FC<SummaryStatsProps> = ({
  totalPaymentsCount,
  totalVolumeXLM,
  activeWalletsCount,
  rates,
}) => {
  const [selectedCurrency, setSelectedCurrency] = useState<CurrencyCode>('XLM');
  const [liveRates, setLiveRates] = useState<Record<CurrencyCode, number>>(FALLBACK_XLM_RATES);
  const [rateStatus, setRateStatus] = useState<'loading' | 'live' | 'fallback'>('loading');

  useEffect(() => {
    let isMounted = true;

    if (rates) {
      return () => {
        isMounted = false;
      };
    }

    fetchXlmFiatRates()
      .then((nextRates) => {
        if (!isMounted) return;
        setLiveRates(nextRates);
        setRateStatus('live');
      })
      .catch(() => {
        if (!isMounted) return;
        setRateStatus('fallback');
      });

    return () => {
      isMounted = false;
    };
  }, [rates]);

  const resolvedRateStatus = rates ? 'live' : rateStatus;

  const resolvedRates = useMemo(
    () => ({
      ...FALLBACK_XLM_RATES,
      ...liveRates,
      ...rates,
    }),
    [liveRates, rates]
  );

  const convertedVolume = convertXlmAmount(totalVolumeXLM, selectedCurrency, resolvedRates);
  const showConvertedFiat = selectedCurrency !== 'XLM';

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl shadow-xl hover:border-purple-500/30 transition-all duration-300">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            <span className="text-sm font-medium text-slate-400">Total Volume Tracked</span>
            <div className="mt-2 flex flex-wrap gap-2" aria-label="Select display currency">
              {CURRENCY_OPTIONS.map((option) => (
                <button
                  key={option.code}
                  type="button"
                  data-testid={`currency-toggle-${option.code}`}
                  onClick={() => setSelectedCurrency(option.code)}
                  className={`px-2.5 py-1 rounded-lg border text-[11px] font-semibold transition-colors ${
                    selectedCurrency === option.code
                      ? 'bg-purple-500/20 border-purple-400/60 text-purple-100'
                      : 'bg-slate-950/40 border-slate-700/80 text-slate-400 hover:text-slate-200 hover:border-slate-500'
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>
          <span className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            ????
          </span>
        </div>
        <div className="flex flex-col gap-1">
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold tracking-tight text-white">
              {formatCurrencyAmount(convertedVolume, selectedCurrency)}
            </span>
          </div>
          {showConvertedFiat && (
            <span className="text-xs font-medium text-slate-500">
              {totalVolumeXLM.toLocaleString(undefined, {
                minimumFractionDigits: 2,
                maximumFractionDigits: 2,
              })}{' '}
              XLM at {resolvedRates[selectedCurrency].toFixed(4)} {selectedCurrency}/XLM
            </span>
          )}
          <span
            className={`mt-2 inline-flex w-fit rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
              resolvedRateStatus === 'live'
                ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20'
                : resolvedRateStatus === 'loading'
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20'
                  : 'bg-amber-500/10 text-amber-300 border border-amber-500/20'
            }`}
          >
            {resolvedRateStatus === 'live' ? 'Live rates' : resolvedRateStatus === 'loading' ? 'Loading rates' : 'Fallback rates'}
          </span>
        </div>
      </div>

      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl shadow-xl hover:border-blue-500/30 transition-all duration-300">
        <div className="flex items-center justify-between mb-4">
          <span className="text-sm font-medium text-slate-400">Total Ingested Payments</span>
          <span className="p-2.5 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
            ???
          </span>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-bold tracking-tight text-white">
            {totalPaymentsCount}
          </span>
          <span className="text-xs font-semibold text-slate-400">payments</span>
        </div>
      </div>

      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl shadow-xl hover:border-emerald-500/30 transition-all duration-300">
        <div className="flex items-center justify-between mb-4">
          <span className="text-sm font-medium text-slate-400">Monitored Wallets</span>
          <span className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            ????
          </span>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-bold tracking-tight text-white">
            {activeWalletsCount}
          </span>
          <span className="text-xs font-semibold text-emerald-400">active</span>
        </div>
      </div>
    </div>
  );
};